using L402Requests.Wallets;

namespace L402Requests;

/// <summary>
/// HTTP client with automatic L402 payment handling.
/// Wraps HttpClient and automatically pays Lightning invoices on 402 responses.
/// </summary>
public sealed class L402HttpClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private IWallet? _wallet;
    private readonly BudgetController? _budget;
    private readonly CredentialCache _cache;

    /// <summary>
    /// Payment history for this client instance.
    /// </summary>
    public SpendingLog SpendingLog { get; } = new();

    /// <summary>
    /// Create an L402 HTTP client with auto-detected wallet and default options.
    /// </summary>
    public L402HttpClient()
        : this(wallet: null, options: null)
    {
    }

    /// <summary>
    /// Create an L402 HTTP client with a specific wallet.
    /// </summary>
    public L402HttpClient(IWallet wallet)
        : this(wallet, options: null)
    {
    }

    /// <summary>
    /// Create an L402 HTTP client with specific options.
    /// </summary>
    public L402HttpClient(L402Options options)
        : this(options.Wallet, options)
    {
    }

    /// <summary>
    /// Create an L402 HTTP client with optional wallet and options.
    /// </summary>
    public L402HttpClient(IWallet? wallet = null, L402Options? options = null)
    {
        _wallet = wallet ?? options?.Wallet;
        var opts = options ?? new L402Options();
        _budget = opts.BudgetEnabled ? new BudgetController(opts) : null;
        _cache = new CredentialCache(opts.CacheMaxSize, opts.CacheTtlSeconds);
        _httpClient = new HttpClient();
        _ownsHttpClient = true;
    }

    internal L402HttpClient(HttpClient httpClient, IWallet? wallet, BudgetController? budget, CredentialCache cache)
    {
        _httpClient = httpClient;
        _ownsHttpClient = false;
        _wallet = wallet;
        _budget = budget;
        _cache = cache;
    }

    /// <summary>Send an HTTP request, auto-paying L402 challenges.</summary>
    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct = default)
    {
        var url = request.RequestUri?.ToString() ?? throw new ArgumentException("Request must have a URI");
        var uri = request.RequestUri!;

        // Try cached credential first
        var cachedCred = _cache.Get(uri.Host, uri.AbsolutePath);
        if (cachedCred is not null)
            request.Headers.TryAddWithoutValidation("Authorization", cachedCred.AuthorizationHeader);

        var response = await _httpClient.SendAsync(request, ct);

        if ((int)response.StatusCode != 402)
            return response;

        // Parse L402 challenge
        var challenge = L402Challenge.TryParse(response);
        if (challenge is null)
            return response; // 402 but not L402 — return as-is

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

        return await _httpClient.SendAsync(retryRequest, ct);
    }

    /// <summary>Send a GET request, auto-paying L402 challenges.</summary>
    public Task<HttpResponseMessage> GetAsync(string url, CancellationToken ct = default)
        => SendAsync(new HttpRequestMessage(HttpMethod.Get, url), ct);

    /// <summary>Send a POST request, auto-paying L402 challenges.</summary>
    public Task<HttpResponseMessage> PostAsync(string url, HttpContent? content, CancellationToken ct = default)
        => SendAsync(new HttpRequestMessage(HttpMethod.Post, url) { Content = content }, ct);

    /// <summary>Send a PUT request, auto-paying L402 challenges.</summary>
    public Task<HttpResponseMessage> PutAsync(string url, HttpContent? content, CancellationToken ct = default)
        => SendAsync(new HttpRequestMessage(HttpMethod.Put, url) { Content = content }, ct);

    /// <summary>Send a PATCH request, auto-paying L402 challenges.</summary>
    public Task<HttpResponseMessage> PatchAsync(string url, HttpContent? content, CancellationToken ct = default)
        => SendAsync(new HttpRequestMessage(HttpMethod.Patch, url) { Content = content }, ct);

    /// <summary>Send a DELETE request, auto-paying L402 challenges.</summary>
    public Task<HttpResponseMessage> DeleteAsync(string url, CancellationToken ct = default)
        => SendAsync(new HttpRequestMessage(HttpMethod.Delete, url), ct);

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
        if (_wallet is IDisposable disposable)
            disposable.Dispose();
    }

    private IWallet GetWallet()
    {
        _wallet ??= WalletDetector.DetectWallet();
        return _wallet;
    }

    private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage original)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);

        // Copy headers
        foreach (var header in original.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        // Copy content
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
