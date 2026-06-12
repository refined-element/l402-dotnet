using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace L402Requests.Wallets;

/// <summary>
/// Pay invoices via LND REST API.
/// Requires: LND_REST_HOST, LND_MACAROON_HEX environment variables.
/// </summary>
public sealed class LndWallet : IWallet, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;

    public string Name => "LND";
    public bool SupportsPreimage => true;

    /// <summary>
    /// Creates an LND REST wallet.
    /// </summary>
    /// <param name="host">LND REST base URL (e.g. https://localhost:8080).</param>
    /// <param name="macaroonHex">Hex-encoded macaroon for the Grpc-Metadata-macaroon header.</param>
    /// <param name="tlsCertPath">
    /// Optional path to the node's TLS certificate. When supplied, the presented server
    /// certificate is pinned: the handshake only succeeds if the server presents this exact
    /// certificate. This is the recommended setup for LND's self-signed certs.
    /// </param>
    /// <param name="insecure">
    /// Opt-in switch to disable TLS server-certificate validation entirely (accept ANY cert).
    /// Defaults to <c>false</c> (secure). Can also be enabled via the <c>LND_INSECURE</c>
    /// environment variable (set to <c>1</c>/<c>true</c>). Only use this on a trusted local
    /// loopback connection — it permits man-in-the-middle interception of the LND REST traffic
    /// (including the macaroon). Prefer <paramref name="tlsCertPath"/> instead.
    /// </param>
    public LndWallet(string host, string macaroonHex, string? tlsCertPath = null, bool insecure = false)
    {
        var handler = new HttpClientHandler();

        // Honour LND_INSECURE as an opt-in escape hatch in addition to the constructor flag.
        // The SECURE behaviour is the default; insecure must be explicitly requested.
        var insecureOptIn = insecure || IsInsecureEnvOptIn();

        X509Certificate2? pinnedCert = null;
        if (!string.IsNullOrEmpty(tlsCertPath))
        {
            // Load the node's TLS cert purely to pin the SERVER certificate (thumbprint
            // comparison in ValidateServerCertificate). Do NOT add it to
            // handler.ClientCertificates — that configures CLIENT authentication (mTLS),
            // which is not what server-cert pinning needs. Worse, this cert has no private
            // key, so if the server ever requests a client cert the handshake would fail.
            pinnedCert = new X509Certificate2(tlsCertPath);
        }

        // Only install a custom validation callback when we have something specific to do:
        // a pinned cert to verify against, or an explicit insecure opt-in. Otherwise we leave
        // the callback unset so the platform's default chain validation applies (which is what
        // a properly-CA-signed LND endpoint needs). The old code blindly returned `true` in
        // every case, accepting any server cert and enabling MITM on the REST connection.
        if (pinnedCert != null || insecureOptIn)
        {
            var capturedPin = pinnedCert;
            handler.ServerCertificateCustomValidationCallback =
                (_, serverCert, chain, errors) =>
                    ValidateServerCertificate(capturedPin, insecureOptIn, serverCert, chain, errors);
        }

        _httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri(host.TrimEnd('/')),
            Timeout = TimeSpan.FromSeconds(60),
        };
        _httpClient.DefaultRequestHeaders.Add("Grpc-Metadata-macaroon", macaroonHex);
        _ownsHttpClient = true;
    }

    private static bool IsInsecureEnvOptIn()
    {
        var v = Environment.GetEnvironmentVariable("LND_INSECURE");
        if (string.IsNullOrWhiteSpace(v)) return false;
        v = v.Trim();
        // Accepted opt-in values are exactly "1" / "true" (case-insensitive for "true"),
        // matching the LND_INSECURE XML doc on the constructor.
        return v.Equals("1", StringComparison.Ordinal)
            || v.Equals("true", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// TLS server-certificate validation policy for the LND REST connection.
    /// <list type="bullet">
    /// <item><description>If <paramref name="insecure"/> is opted in, accept any certificate (MITM-permitting; explicit opt-in only).</description></item>
    /// <item><description>If a <paramref name="pinnedCert"/> is supplied, accept only when the presented
    /// <paramref name="serverCert"/> exactly matches the pinned certificate (thumbprint compared in
    /// constant time). This trusts LND's self-signed cert without trusting anything else.</description></item>
    /// <item><description>Otherwise defer to the platform: accept only when there are no
    /// <see cref="SslPolicyErrors"/>.</description></item>
    /// </list>
    /// Exposed <c>internal</c> for unit testing.
    /// </summary>
    internal static bool ValidateServerCertificate(
        X509Certificate2? pinnedCert,
        bool insecure,
        X509Certificate2? serverCert,
        X509Chain? chain,
        SslPolicyErrors sslErrors)
    {
        // Explicit insecure opt-in: caller knowingly disabled validation.
        if (insecure)
            return true;

        // Certificate pinning: the presented server cert must be exactly the pinned one.
        if (pinnedCert != null)
        {
            if (serverCert == null)
                return false;

            // Compare SHA-256 thumbprints in constant time (project Standard #7 — no plain
            // == on security material). GetCertHash(SHA256) avoids the legacy SHA-1 Thumbprint.
            var pinnedHash = pinnedCert.GetCertHash(HashAlgorithmName.SHA256);
            var presentedHash = serverCert.GetCertHash(HashAlgorithmName.SHA256);
            return CryptographicOperations.FixedTimeEquals(pinnedHash, presentedHash);
        }

        // No pin, not insecure: trust the platform's chain/name validation result.
        return sslErrors == SslPolicyErrors.None;
    }

    internal LndWallet(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _ownsHttpClient = false;
    }

    /// <summary>
    /// Pay via LND's v2/router/send (streaming JSON response).
    /// Extracts preimage (base64 → hex) from the final payment state.
    /// </summary>
    public async Task<string> PayInvoiceAsync(string bolt11, CancellationToken ct = default)
    {
        HttpResponseMessage response;
        try
        {
            response = await _httpClient.PostAsJsonAsync(
                "/v2/router/send",
                new
                {
                    payment_request = bolt11,
                    timeout_seconds = 60,
                    fee_limit_sat = 100
                },
                ct);
        }
        catch (HttpRequestException e)
        {
            throw new PaymentFailedException($"LND connection error: {e.Message}", bolt11);
        }

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            throw new PaymentFailedException(
                $"LND returned {(int)response.StatusCode}: {body}", bolt11);
        }

        var responseText = await response.Content.ReadAsStringAsync(ct);

        // v2/router/send returns newline-delimited JSON stream
        // Parse the last complete JSON object for the final payment state
        JsonElement? lastUpdate = null;
        foreach (var line in responseText.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                lastUpdate = doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                continue;
            }
        }

        if (!lastUpdate.HasValue)
            throw new PaymentFailedException("No response from LND router", bolt11);

        var result = lastUpdate.Value.TryGetProperty("result", out var r) ? r : lastUpdate.Value;
        var status = result.TryGetProperty("status", out var s) ? s.GetString() ?? "" : "";

        if (status == "SUCCEEDED")
        {
            var preimage = result.TryGetProperty("payment_preimage", out var pi)
                ? pi.GetString() ?? ""
                : "";

            if (string.IsNullOrEmpty(preimage))
                throw new PaymentFailedException("LND payment succeeded but no preimage returned", bolt11);

            // LND returns base64-encoded preimage, convert to hex
            try
            {
                var bytes = Convert.FromBase64String(preimage);
                return Convert.ToHexString(bytes).ToLowerInvariant();
            }
            catch (FormatException)
            {
                // Already hex
                return preimage;
            }
        }
        else if (status == "FAILED")
        {
            var failureReason = result.TryGetProperty("failure_reason", out var fr)
                ? fr.GetString() ?? "unknown"
                : "unknown";
            throw new PaymentFailedException($"LND payment failed: {failureReason}", bolt11);
        }
        else
        {
            throw new PaymentFailedException($"LND unexpected status: {status}", bolt11);
        }
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
