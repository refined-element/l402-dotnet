using System.Net.Http.Json;
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

    public LndWallet(string host, string macaroonHex, string? tlsCertPath = null)
    {
        var handler = new HttpClientHandler();

        if (!string.IsNullOrEmpty(tlsCertPath))
        {
            handler.ClientCertificates.Add(new X509Certificate2(tlsCertPath));
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }
        else
        {
            // For self-signed LND certs
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }

        _httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri(host.TrimEnd('/')),
            Timeout = TimeSpan.FromSeconds(60),
        };
        _httpClient.DefaultRequestHeaders.Add("Grpc-Metadata-macaroon", macaroonHex);
        _ownsHttpClient = true;
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
