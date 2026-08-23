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

        // Advertise draft-00 Payment support (optional per the spec; servers
        // that don't know the header ignore it).
        if (!request.Headers.Contains("Accept-Payment"))
            request.Headers.TryAddWithoutValidation("Accept-Payment", "lightning/charge");

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

        // An expired modern challenge cannot produce a credential the server
        // must accept — refuse before any funds move.
        if (challenge is ModernPaymentChallenge expiredCheck && expiredCheck.IsExpired)
            throw new ChallengeExpiredException(expiredCheck.Expires);

        // Extract amount and check budget. Prefer the BOLT11-encoded amount, but
        // only when it is strictly positive (PositiveSatsOrNull guards the literal-
        // zero blank cheque); otherwise fall back to the challenge's amount
        // parameter (legacy MPP header param, or the modern decoded request amount).
        var amountSats = PositiveSatsOrNull(Bolt11Invoice.ExtractAmountSats(challenge.Invoice))
            ?? MppAmountToSats(challenge switch
            {
                MppChallenge mppForBudget => mppForBudget.Amount,
                ModernPaymentChallenge modernForBudget => modernForBudget.Amount,
                _ => null,
            });
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

        // Reserve budget atomically BEFORE paying. TryReserve evaluates the domain
        // allowlist and the per-request/hour/day caps under one lock, counting other
        // in-flight reservations, and records this spend as reserved — so two concurrent
        // payments cannot both pass a check against the same pre-payment total and both
        // settle (the check-then-pay-then-record TOCTOU). Refusal throws, as Check did.
        // Budget is reserved before the wallet-capability check so an over-budget request
        // is refused with BudgetExceededException regardless of the wallet.
        long? reservationId = _budget?.TryReserve(amountSats.Value, domain);

        // Pay the invoice
        IWallet wallet;
        try
        {
            wallet = GetWallet();
            RejectWalletWithoutPreimage(wallet);
        }
        catch
        {
            // Release the reservation if the wallet can't be used — no funds moved.
            if (reservationId.HasValue)
                _budget?.Release(reservationId.Value);
            throw;
        }

        string preimage;
        try
        {
            preimage = await wallet.PayInvoiceAsync(challenge.Invoice, ct);
        }
        catch (Exception e)
        {
            // Payment failed: release the reservation so it doesn't hold budget forever.
            if (reservationId.HasValue)
                _budget?.Release(reservationId.Value);
            SpendingLog.Record(domain, uri.AbsolutePath, amountSats.Value, "", success: false, macaroon: challengeMacaroon);

            if (e is L402Exception)
                throw;
            throw new PaymentFailedException(e.Message, challenge.Invoice);
        }

        // Commit the reserved spend into the budget window. amountSats is always known by
        // this point — unknown amounts were refused above — so every payment the client
        // makes lands in the budget and the log, with no silent gaps. The wallet returns
        // only the preimage; routing fees are not surfaced by IWallet.PayInvoiceAsync, so
        // we commit the invoice principal. If a wallet later exposes the paid fee, add it
        // to the committed amount here.
        if (reservationId.HasValue)
            _budget?.Commit(reservationId.Value, amountSats.Value);
        var record = SpendingLog.Record(domain, uri.AbsolutePath, amountSats.Value, preimage, success: true, macaroon: challengeMacaroon);

        // Build the retry Authorization header. Modern draft-00 credentials are
        // SINGLE-USE server-side, so they are never cached; L402 and legacy MPP
        // credentials keep their cache-and-reuse behavior (using the Put return
        // value directly avoids a second cache lookup that could fail if the
        // cache evicts immediately).
        string authorizationValue;
        if (challenge is ModernPaymentChallenge modernChallenge)
            authorizationValue = modernChallenge.BuildAuthorizationHeader(preimage);
        else if (challenge is L402Challenge l402Cached)
            authorizationValue = _cache.Put(domain, uri.AbsolutePath, l402Cached.Macaroon, preimage).AuthorizationHeader;
        else
            authorizationValue = _cache.PutMpp(domain, uri.AbsolutePath, preimage).AuthorizationHeader;

        // Retry with the freshly built authorization header
        var retryRequest = await CloneRequestAsync(request);
        retryRequest.Headers.Remove("Authorization");
        retryRequest.Headers.TryAddWithoutValidation("Authorization", authorizationValue);

        var paidResponse = await _httpClient.SendAsync(retryRequest, ct);

        // Surface the server's Payment-Receipt (draft-00) when present. Tolerant:
        // an absent or malformed receipt never fails the successful payment.
        var receipt = PaymentReceipt.TryParse(paidResponse);
        if (receipt is not null)
            SpendingLog.AttachReceipt(record, receipt);

        return paidResponse;
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
