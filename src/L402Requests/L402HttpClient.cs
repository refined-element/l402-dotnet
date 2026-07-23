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

        // Parse payment challenge (prefers L402, falls back to MPP)
        var challenge = L402Challenge.TryParsePaymentChallenge(response);
        if (challenge is null)
            return response; // 402 but not L402/MPP — return as-is

        // Extract amount and check budget. Prefer the BOLT11-encoded amount, but
        // only when it is strictly positive (PositiveSatsOrNull guards the literal-
        // zero blank cheque); otherwise fall back to the MPP amount parameter.
        var amountSats = PositiveSatsOrNull(Bolt11Invoice.ExtractAmountSats(challenge.Invoice))
            ?? (challenge is MppChallenge mppForBudget ? MppAmountToSats(mppForBudget.Amount) : null);
        var domain = uri.Host;

        // Macaroon from the parsed challenge, recorded at payment time so two-step
        // flows can rebuild "L402 {macaroon}:{preimage}". MPP challenges have none.
        var challengeMacaroon = challenge is L402Challenge l402Challenge ? l402Challenge.Macaroon : "";

        // An amount we can't determine is an amount we can't authorise. Paying anyway
        // would skip Check() entirely — and that call is not just the per-request/hour/day
        // sats limits but the domain allowlist too — while the spend would never reach the
        // log below, hiding it from every LATER budget check. A server after a blank cheque
        // need only send an amountless invoice. Refuse before any funds move.
        if (!amountSats.HasValue)
            throw new InvoiceAmountUnknownException(
                Bolt11Invoice.ClassifyMissingAmount(challenge.Invoice), challenge.Invoice);

        _budget?.Check(amountSats.Value, domain);

        // Pay the invoice
        var wallet = GetWallet();
        RejectWalletWithoutPreimage(wallet);
        string preimage;
        try
        {
            preimage = await wallet.PayInvoiceAsync(challenge.Invoice, ct);
        }
        catch (Exception e)
        {
            SpendingLog.Record(domain, uri.AbsolutePath, amountSats.Value, "", success: false, macaroon: challengeMacaroon);

            if (e is L402Exception)
                throw;
            throw new PaymentFailedException(e.Message, challenge.Invoice);
        }

        // Record successful payment. amountSats is always known by this point — unknown
        // amounts were refused above — so every payment the client makes lands in the
        // budget and the log, with no silent gaps.
        _budget?.RecordPayment(amountSats.Value);
        SpendingLog.Record(domain, uri.AbsolutePath, amountSats.Value, preimage, success: true, macaroon: challengeMacaroon);

        // Cache the credential and use the returned credential directly for the retry header.
        // This avoids a second cache lookup that could fail if the cache evicts immediately.
        L402Credential credential;
        if (challenge is L402Challenge l402Cached)
            credential = _cache.Put(domain, uri.AbsolutePath, l402Cached.Macaroon, preimage);
        else
            credential = _cache.PutMpp(domain, uri.AbsolutePath, preimage);

        // Retry with authorization header constructed directly from the credential
        var retryRequest = await CloneRequestAsync(request);
        retryRequest.Headers.Remove("Authorization");
        retryRequest.Headers.TryAddWithoutValidation("Authorization", credential.AuthorizationHeader);

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

    /// <summary>
    /// Fail fast on a wallet that can't surface a payment preimage.
    /// </summary>
    /// <remarks>
    /// L402's retry needs the preimage to build the Authorization header, so paying with
    /// such a wallet (OpenNode) would spend funds for no access — the invoice settles and
    /// the credential still can't be assembled. Checked before the payment, not after it.
    /// Shared by <see cref="L402HttpClient"/> and <see cref="L402DelegatingHandler"/> so
    /// both surfaces refuse identically.
    /// </remarks>
    /// <exception cref="UnsupportedWalletException">If the wallet has no preimage support.</exception>
    internal static void RejectWalletWithoutPreimage(IWallet wallet)
    {
        if (!wallet.SupportsPreimage)
            throw new UnsupportedWalletException(
                "configured wallet does not return Lightning payment preimages, which L402 " +
                "requires. Use Strike, LND, or a compatible NWC wallet (CoinOS, CLINK, " +
                "Alby Hub) instead.");
    }

    /// <summary>
    /// Parse an MPP amount string (assumed to be in satoshis) as a fallback
    /// when the BOLT11 invoice encodes no amount (zero-amount invoice).
    /// Returns null if the value is missing, not a valid integer, or not a positive amount.
    /// </summary>
    internal static int? MppAmountToSats(string? amount)
    {
        if (string.IsNullOrWhiteSpace(amount))
            return null;
        return int.TryParse(amount, out var sats) && sats > 0 ? sats : null;
    }

    /// <summary>
    /// Collapse a non-positive BOLT11 amount to null so the resolved amount is
    /// strictly positive from the BOLT11 branch too, not merely non-null.
    /// </summary>
    /// <remarks>
    /// A literal-zero invoice ("lnbc0p1...") DECODES to 0, not null — the amount
    /// field is present, it is just zero — so a bare "?? MppAmountToSats(...)"
    /// short-circuits on the 0, Check(0) passes, and the wallet (not the server)
    /// then picks the spend: the same blank-cheque hole ledger #42 closes on the
    /// MPP branch. Mapping &lt;= 0 to null lets it fall through to the MPP amount
    /// (itself guarded) or, failing that, onto the refusal path.
    /// </remarks>
    internal static int? PositiveSatsOrNull(int? sats) => sats is > 0 ? sats : null;

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
