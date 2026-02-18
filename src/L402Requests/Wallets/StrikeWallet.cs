using System.Net.Http.Json;
using System.Text.Json;

namespace L402Requests.Wallets;

/// <summary>
/// Pay invoices via Strike REST API.
/// Requires: STRIKE_API_KEY environment variable.
/// Strike provides full preimage support and requires no infrastructure.
/// </summary>
public sealed class StrikeWallet : IWallet, IDisposable
{
    private const string DefaultBaseUrl = "https://api.strike.me";
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;

    public string Name => "Strike";
    public bool SupportsPreimage => true;

    public StrikeWallet(string apiKey, string? baseUrl = null)
    {
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri((baseUrl ?? DefaultBaseUrl).TrimEnd('/')),
            Timeout = TimeSpan.FromSeconds(60),
        };
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");
        _ownsHttpClient = true;
    }

    internal StrikeWallet(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _ownsHttpClient = false;
    }

    /// <summary>
    /// Pay via Strike's quote + execute flow.
    /// 1. POST /v1/payment-quotes/lightning — create quote
    /// 2. PATCH /v1/payment-quotes/{id}/execute — execute
    /// 3. Extract preimage from response
    /// </summary>
    public async Task<string> PayInvoiceAsync(string bolt11, CancellationToken ct = default)
    {
        // Step 1: Create payment quote
        HttpResponseMessage quoteResp;
        try
        {
            quoteResp = await _httpClient.PostAsJsonAsync(
                "/v1/payment-quotes/lightning",
                new { lnInvoice = bolt11, sourceCurrency = "BTC" },
                ct);
        }
        catch (HttpRequestException e)
        {
            throw new PaymentFailedException($"Strike connection error: {e.Message}", bolt11);
        }

        if (!quoteResp.IsSuccessStatusCode)
        {
            var body = await quoteResp.Content.ReadAsStringAsync(ct);
            throw new PaymentFailedException(
                $"Strike quote failed ({(int)quoteResp.StatusCode}): {body}", bolt11);
        }

        using var quoteDoc = await JsonDocument.ParseAsync(
            await quoteResp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var quoteId = quoteDoc.RootElement.GetProperty("paymentQuoteId").GetString();

        if (string.IsNullOrEmpty(quoteId))
            throw new PaymentFailedException("Strike quote missing paymentQuoteId", bolt11);

        // Step 2: Execute payment
        HttpResponseMessage execResp;
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Patch, $"/v1/payment-quotes/{quoteId}/execute");
            execResp = await _httpClient.SendAsync(request, ct);
        }
        catch (HttpRequestException e)
        {
            throw new PaymentFailedException($"Strike execution error: {e.Message}", bolt11);
        }

        if (!execResp.IsSuccessStatusCode)
        {
            var body = await execResp.Content.ReadAsStringAsync(ct);
            throw new PaymentFailedException(
                $"Strike execution failed ({(int)execResp.StatusCode}): {body}", bolt11);
        }

        using var paymentDoc = await JsonDocument.ParseAsync(
            await execResp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var root = paymentDoc.RootElement;

        // Extract preimage from Lightning payment details
        var preimage = TryGetPreimage(root);

        if (string.IsNullOrEmpty(preimage))
        {
            // Try fetching payment details
            var paymentId = TryGetString(root, "paymentId") ?? TryGetString(root, "paymentQuoteId");
            if (!string.IsNullOrEmpty(paymentId))
                preimage = await FetchPreimageAsync(paymentId, ct);
        }

        if (string.IsNullOrEmpty(preimage))
            throw new PaymentFailedException(
                "Strike payment succeeded but no preimage returned. " +
                "This may happen with older Strike API versions.", bolt11);

        return preimage;
    }

    private static string? TryGetPreimage(JsonElement root)
    {
        if (root.TryGetProperty("lightning", out var lightning))
        {
            if (lightning.TryGetProperty("preImage", out var pi1))
                return pi1.GetString();
            if (lightning.TryGetProperty("preimage", out var pi2))
                return pi2.GetString();
        }
        if (root.TryGetProperty("preimage", out var pi3))
            return pi3.GetString();
        return null;
    }

    private static string? TryGetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var val) ? val.GetString() : null;
    }

    private async Task<string?> FetchPreimageAsync(string paymentId, CancellationToken ct)
    {
        try
        {
            var resp = await _httpClient.GetAsync($"/v1/payments/{paymentId}", ct);
            if (resp.IsSuccessStatusCode)
            {
                using var doc = await JsonDocument.ParseAsync(
                    await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
                return TryGetPreimage(doc.RootElement);
            }
        }
        catch (HttpRequestException)
        {
            // Ignore — best-effort preimage fetch
        }
        return null;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
