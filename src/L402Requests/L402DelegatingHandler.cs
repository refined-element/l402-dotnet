using L402Requests.Wallets;

namespace L402Requests;

/// <summary>
/// HttpMessageHandler for L402 auto-payment, designed for use with IHttpClientFactory.
/// Same L402 logic as L402HttpClient but as a DelegatingHandler in the pipeline.
/// </summary>
public sealed class L402DelegatingHandler : DelegatingHandler
{
    private IWallet? _wallet;
    private readonly BudgetController? _budget;
    private readonly CredentialCache _cache;

    /// <summary>
    /// Payment history for this handler instance.
    /// </summary>
    public SpendingLog SpendingLog { get; } = new();

    public L402DelegatingHandler(
        IWallet? wallet = null,
        BudgetController? budget = null,
        CredentialCache? cache = null)
    {
        _wallet = wallet;
        _budget = budget;
        _cache = cache ?? new CredentialCache();
    }

    public L402DelegatingHandler(L402Options options)
    {
        _wallet = options.Wallet;
        _budget = options.BudgetEnabled ? new BudgetController(options) : null;
        _cache = new CredentialCache(options.CacheMaxSize, options.CacheTtlSeconds);
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var uri = request.RequestUri ?? throw new ArgumentException("Request must have a URI");

        // Try cached credential first
        var cachedCred = _cache.Get(uri.Host, uri.AbsolutePath);
        if (cachedCred is not null)
            request.Headers.TryAddWithoutValidation("Authorization", cachedCred.AuthorizationHeader);

        var response = await base.SendAsync(request, ct);

        if ((int)response.StatusCode != 402)
            return response;

        // Parse L402 challenge
        var challenge = L402Challenge.TryParse(response);
        if (challenge is null)
            return response;

        // Extract amount and check budget
        var amountSats = Bolt11Invoice.ExtractAmountSats(challenge.Invoice);
        var domain = uri.Host;

        if (_budget is not null && amountSats.HasValue)
            _budget.Check(amountSats.Value, domain);

        // Pay the invoice
        var wallet = GetWallet();
        string preimage;
        try
        {
            preimage = await wallet.PayInvoiceAsync(challenge.Invoice, ct);
        }
        catch (Exception e)
        {
            if (amountSats.HasValue)
                SpendingLog.Record(domain, uri.AbsolutePath, amountSats.Value, "", success: false);

            if (e is L402Exception)
                throw;
            throw new PaymentFailedException(e.Message, challenge.Invoice);
        }

        // Record successful payment
        if (amountSats.HasValue)
        {
            _budget?.RecordPayment(amountSats.Value);
            SpendingLog.Record(domain, uri.AbsolutePath, amountSats.Value, preimage, success: true);
        }

        // Cache the credential
        _cache.Put(domain, uri.AbsolutePath, challenge.Macaroon, preimage);

        // Retry with L402 authorization
        var retryRequest = await CloneRequestAsync(request);
        retryRequest.Headers.Remove("Authorization");
        retryRequest.Headers.TryAddWithoutValidation("Authorization", $"L402 {challenge.Macaroon}:{preimage}");

        return await base.SendAsync(retryRequest, ct);
    }

    private IWallet GetWallet()
    {
        _wallet ??= WalletDetector.DetectWallet();
        return _wallet;
    }

    private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage original)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);

        foreach (var header in original.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        if (original.Content is not null)
        {
            var content = await original.Content.ReadAsByteArrayAsync();
            clone.Content = new ByteArrayContent(content);

            foreach (var header in original.Content.Headers)
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return clone;
    }
}
