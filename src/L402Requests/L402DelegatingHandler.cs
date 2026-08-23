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

        // Advertise draft-00 Payment support (optional per the spec; servers
        // that don't know the header ignore it).
        if (!request.Headers.Contains("Accept-Payment"))
            request.Headers.TryAddWithoutValidation("Accept-Payment", "lightning/charge");

        // Try cached credential first
        var cachedCred = _cache.Get(uri.Host, uri.AbsolutePath);
        if (cachedCred is not null)
            request.Headers.TryAddWithoutValidation("Authorization", cachedCred.AuthorizationHeader);

        var response = await base.SendAsync(request, ct);

        if ((int)response.StatusCode != 402)
            return response;

        // Parse payment challenge (prefers L402, falls back to MPP)
        var challenge = L402Challenge.TryParsePaymentChallenge(response);
        if (challenge is null)
            return response;

        // An expired modern challenge cannot produce a credential the server
        // must accept — refuse before any funds move.
        if (challenge is ModernPaymentChallenge expiredCheck && expiredCheck.IsExpired)
            throw new ChallengeExpiredException(expiredCheck.Expires);

        // Extract amount and check budget. Prefer the BOLT11-encoded amount, but
        // only when it is strictly positive (PositiveSatsOrNull guards the literal-
        // zero blank cheque); otherwise fall back to the challenge's amount
        // parameter (legacy MPP header param, or the modern decoded request amount).
        var amountSats = L402HttpClient.PositiveSatsOrNull(Bolt11Invoice.ExtractAmountSats(challenge.Invoice))
            ?? L402HttpClient.MppAmountToSats(challenge switch
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
            L402HttpClient.RejectWalletWithoutPreimage(wallet);
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
        // this point — unknown amounts were refused above — so every payment lands in the
        // budget and the log. The wallet returns only the preimage; routing fees are not
        // surfaced by IWallet.PayInvoiceAsync, so we commit the invoice principal. If a
        // wallet later exposes the paid fee, add it to the committed amount here.
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

        var paidResponse = await base.SendAsync(retryRequest, ct);

        // Surface the server's Payment-Receipt (draft-00) when present. Tolerant:
        // an absent or malformed receipt never fails the successful payment.
        var receipt = PaymentReceipt.TryParse(paidResponse);
        if (receipt is not null)
            SpendingLog.AttachReceipt(record, receipt);

        return paidResponse;
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
