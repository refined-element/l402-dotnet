using System.Net.Http.Json;
using System.Text.Json;

namespace L402Requests.Wallets;

/// <summary>
/// Pay invoices via OpenNode REST API.
/// Requires: OPENNODE_API_KEY environment variable.
/// Note: OpenNode does not return preimages, which limits L402 functionality.
/// For full L402 support, use Strike, LND, or a compatible NWC wallet.
/// </summary>
public sealed class OpenNodeWallet : IWallet, IDisposable
{
    private const string DefaultBaseUrl = "https://api.opennode.com";
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;

    public string Name => "OpenNode";
    public bool SupportsPreimage => false;

    public OpenNodeWallet(string apiKey, string? baseUrl = null)
    {
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri((baseUrl ?? DefaultBaseUrl).TrimEnd('/')),
            Timeout = TimeSpan.FromSeconds(60),
        };
        _httpClient.DefaultRequestHeaders.Add("Authorization", apiKey);
        _ownsHttpClient = true;
    }

    internal OpenNodeWallet(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _ownsHttpClient = false;
    }

    /// <summary>
    /// Pay via OpenNode's withdrawal endpoint.
    /// Warning: OpenNode typically does not return the preimage, which means
    /// L402 token construction will fail. Provided for completeness only.
    /// </summary>
    public async Task<string> PayInvoiceAsync(string bolt11, CancellationToken ct = default)
    {
        HttpResponseMessage resp;
        try
        {
            resp = await _httpClient.PostAsJsonAsync(
                "/v2/withdrawals",
                new { type = "ln", address = bolt11 },
                ct);
        }
        catch (HttpRequestException e)
        {
            throw new PaymentFailedException($"OpenNode connection error: {e.Message}", bolt11);
        }

        if (!resp.IsSuccessStatusCode)
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            throw new PaymentFailedException(
                $"OpenNode withdrawal failed ({(int)resp.StatusCode}): {body}", bolt11);
        }

        using var doc = await JsonDocument.ParseAsync(
            await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var root = doc.RootElement;

        var data = root.TryGetProperty("data", out var d) ? d : root;
        var preimage = TryGetString(data, "preimage") ?? TryGetString(data, "payment_preimage");

        if (string.IsNullOrEmpty(preimage))
            throw new PaymentFailedException(
                "OpenNode payment succeeded but no preimage returned. " +
                "OpenNode does not support preimage extraction. " +
                "For L402, use Strike, LND, or a compatible NWC wallet.",
                bolt11);

        return preimage;
    }

    private static string? TryGetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var val) ? val.GetString() : null;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
