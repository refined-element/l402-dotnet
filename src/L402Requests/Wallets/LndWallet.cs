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
public sealed class LndWallet : IWallet, IPaymentLookup, IDisposable
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

        byte[]? pinnedThumbprint = null;
        if (!string.IsNullOrEmpty(tlsCertPath))
        {
            // Load the node's TLS cert purely to pin the SERVER certificate. We extract the
            // SHA-256 thumbprint ONCE here and capture only that byte[] in the validation
            // closure — the X509Certificate2 itself holds unmanaged handles, so we dispose it
            // immediately rather than keeping a live instance alive for the lifetime of the
            // wallet (a per-construction resource leak). Do NOT add the cert to
            // handler.ClientCertificates — that configures CLIENT authentication (mTLS),
            // which is not what server-cert pinning needs. Worse, this cert has no private
            // key, so if the server ever requests a client cert the handshake would fail.
            using var pinnedCert = new X509Certificate2(tlsCertPath);
            pinnedThumbprint = pinnedCert.GetCertHash(HashAlgorithmName.SHA256);
        }

        // Only install a custom validation callback when we have something specific to do:
        // a pinned thumbprint to verify against, or an explicit insecure opt-in. Otherwise we
        // leave the callback unset so the platform's default chain validation applies (which is
        // what a properly-CA-signed LND endpoint needs). The old code blindly returned `true` in
        // every case, accepting any server cert and enabling MITM on the REST connection.
        if (pinnedThumbprint != null || insecureOptIn)
        {
            var capturedPin = pinnedThumbprint;
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
    /// <item><description>If a <paramref name="pinnedThumbprint"/> is supplied, accept only when the presented
    /// <paramref name="serverCert"/>'s SHA-256 thumbprint exactly matches the pinned thumbprint (compared in
    /// constant time). This trusts LND's self-signed cert without trusting anything else.</description></item>
    /// <item><description>Otherwise defer to the platform: accept only when there are no
    /// <see cref="SslPolicyErrors"/>.</description></item>
    /// </list>
    /// Takes the pinned SHA-256 thumbprint as a <c>byte[]</c> (extracted once at construction)
    /// rather than a live <see cref="X509Certificate2"/>, so no unmanaged cert handle is retained
    /// for the lifetime of the wallet. Exposed <c>internal</c> for unit testing.
    /// </summary>
    internal static bool ValidateServerCertificate(
        byte[]? pinnedThumbprint,
        bool insecure,
        X509Certificate2? serverCert,
        X509Chain? chain,
        SslPolicyErrors sslErrors)
    {
        // Explicit insecure opt-in: caller knowingly disabled validation.
        if (insecure)
            return true;

        // Certificate pinning: the presented server cert's thumbprint must match the pinned one.
        if (pinnedThumbprint != null)
        {
            if (serverCert == null)
                return false;

            // Compare SHA-256 thumbprints in constant time (project Standard #7 — no plain
            // == on security material). GetCertHash(SHA256) avoids the legacy SHA-1 Thumbprint.
            var presentedHash = serverCert.GetCertHash(HashAlgorithmName.SHA256);
            return CryptographicOperations.FixedTimeEquals(pinnedThumbprint, presentedHash);
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

    /// <summary>
    /// Look an outgoing payment up by hash via <c>GET /v2/router/track/{payment_hash}</c> (one call).
    /// The router streams the CURRENT state first, so only the first JSON line is read; an
    /// <c>IN_FLIGHT</c> payment answers <see cref="PaymentLookupStatus.Unknown"/> without waiting for it to
    /// settle. gRPC <c>NotFound</c> (code 5, "payment isn't initiated") is definitive: this node never
    /// attempted the payment → <see cref="PaymentLookupStatus.NotPaid"/>; <c>FAILED</c> → NotPaid;
    /// <c>SUCCEEDED</c> with a preimage that opens the hash → Paid. Everything else (transport, auth,
    /// parse errors, a preimage that does not match) → Unknown. Never throws for wallet-side outcomes.
    /// </summary>
    public async Task<PaymentLookupResult> LookupPaymentAsync(string paymentHash, CancellationToken ct = default)
    {
        PaymentLookupSupport.EnsureValidPaymentHash(paymentHash);

        // LND REST encodes bytes path params as URL-safe base64.
        var hashB64Url = Convert.ToBase64String(Convert.FromHexString(paymentHash)).Replace('+', '-').Replace('/', '_');

        try
        {
            using var response = await _httpClient.GetAsync(
                $"/v2/router/track/{hashB64Url}?no_inflight_updates=false",
                HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

            // The gateway may report NotFound as an HTTP error or as an error line on a 200 stream.
            using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var reader = new StreamReader(stream);
            string? line;
            while ((line = await reader.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
            {
                line = line.Trim();
                if (line.Length == 0) continue;
                return ClassifyTrackLine(line, paymentHash, response.IsSuccessStatusCode);
            }
            return PaymentLookupResult.Unknown;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or JsonException or FormatException)
        {
            return PaymentLookupResult.Unknown;
        }
    }

    internal static PaymentLookupResult ClassifyTrackLine(string line, string paymentHash, bool httpSuccess)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(line); }
        catch (JsonException) { return PaymentLookupResult.Unknown; }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return PaymentLookupResult.Unknown;

            // gRPC-gateway error shape: {"code": 5, "message": "...", "error": "..."} (code 5 = NotFound).
            if (root.TryGetProperty("code", out var codeEl) && codeEl.ValueKind == JsonValueKind.Number
                && !root.TryGetProperty("result", out _))
            {
                return codeEl.TryGetInt32(out var code) && code == 5 ? PaymentLookupResult.NotPaid : PaymentLookupResult.Unknown;
            }
            if (!httpSuccess) return PaymentLookupResult.Unknown;

            var result = root.TryGetProperty("result", out var r) ? r : root;
            if (result.ValueKind != JsonValueKind.Object) return PaymentLookupResult.Unknown;

            // The reply must be about THIS payment.
            var reportedHash = result.TryGetProperty("payment_hash", out var ph) ? ph.GetString() : null;
            if (!string.IsNullOrEmpty(reportedHash)
                && !string.Equals(reportedHash, paymentHash, StringComparison.OrdinalIgnoreCase))
                return PaymentLookupResult.Unknown;

            var status = result.TryGetProperty("status", out var s) ? s.GetString() ?? "" : "";
            switch (status)
            {
                case "SUCCEEDED":
                {
                    var preimage = NormalizePreimageHex(result.TryGetProperty("payment_preimage", out var pi) ? pi.GetString() : null);
                    if (!PaymentLookupSupport.PreimageOpensHash(preimage, paymentHash))
                        return PaymentLookupResult.Unknown; // settled-but-unprovable is not proof for this hash
                    long? amount = null;
                    if (result.TryGetProperty("value_sat", out var v))
                    {
                        if (v.ValueKind == JsonValueKind.String && long.TryParse(v.GetString(), out var parsed)) amount = parsed;
                        else if (v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var num)) amount = num;
                    }
                    return PaymentLookupResult.Paid(preimage, amount);
                }
                case "FAILED":
                    return PaymentLookupResult.NotPaid;
                default:
                    return PaymentLookupResult.Unknown; // IN_FLIGHT, INITIATED, UNKNOWN
            }
        }
    }

    /// <summary>LND returns the preimage as hex on lnrpc.Payment but base64 on some older paths; normalize to lowercase hex.</summary>
    private static string? NormalizePreimageHex(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return null;
        if (raw.Length == 64)
        {
            try { Convert.FromHexString(raw); return raw.ToLowerInvariant(); }
            catch (FormatException) { }
        }
        try { return Convert.ToHexString(Convert.FromBase64String(raw)).ToLowerInvariant(); }
        catch (FormatException) { return null; }
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
