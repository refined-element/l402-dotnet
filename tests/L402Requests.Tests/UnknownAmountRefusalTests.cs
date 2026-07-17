using System.Net;
using FluentAssertions;
using L402Requests.Wallets;
using Moq;

namespace L402Requests.Tests;

/// <summary>
/// An amount we cannot determine is an amount we cannot authorise.
///
/// <see cref="Bolt11Invoice.ExtractAmountSats"/> returns null both for invoices that
/// encode no amount and for invoices it cannot parse at all. Reading that null as
/// "no limit applies" let a server skip the budget check entirely — and that call is
/// not just the per-request/hour/day sats limits but the domain allowlist too — while
/// the spend never reached the log either, hiding it from every later check as well.
///
/// Covers both payment surfaces: L402HttpClient and L402DelegatingHandler.
/// </summary>
public class UnknownAmountRefusalTests
{
    private const string TestMacaroon = "test_macaroon_abc123";
    private const string TestPreimage = "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567";

    // "lnbc1p..." parses as BOLT11 but encodes no amount.
    private const string NoAmountInvoice = "lnbc1ptest";
    // Not a BOLT11 invoice at all.
    private const string UnparseableInvoice = "not-a-bolt11-invoice";

    private static HttpResponseMessage Create402(string invoice)
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation(
            "WWW-Authenticate", $"L402 macaroon=\"{TestMacaroon}\", invoice=\"{invoice}\"");
        return response;
    }

    private static HttpResponseMessage Create402Mpp(string invoice, string amount)
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation(
            "WWW-Authenticate",
            $"Payment realm=\"api.example.com\", method=\"lightning\", invoice=\"{invoice}\", amount=\"{amount}\", currency=\"sat\"");
        return response;
    }

    private static Mock<IWallet> CreatePayingWallet()
    {
        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.SupportsPreimage).Returns(true);
        mockWallet.Setup(w => w.Name).Returns("Mock");
        mockWallet.Setup(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);
        return mockWallet;
    }

    // ── L402HttpClient ──

    [Fact]
    public async Task HttpClient_NoAmountInvoice_RefusesWithoutPaying()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402(NoAmountInvoice));

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object,
            new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        var act = () => client.GetAsync("https://example.com/paid-resource");

        var ex = await act.Should().ThrowAsync<InvoiceAmountUnknownException>();
        ex.Which.Reason.Should().Be(MissingAmountReason.NoAmountEncoded);
        // Refused BEFORE spending, and nothing recorded as spent.
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        client.SpendingLog.Count.Should().Be(0);
    }

    [Fact]
    public async Task HttpClient_UnparseableInvoice_RefusesWithoutPaying()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402(UnparseableInvoice));

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object,
            new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        var act = () => client.GetAsync("https://example.com/paid-resource");

        var ex = await act.Should().ThrowAsync<InvoiceAmountUnknownException>();
        ex.Which.Reason.Should().Be(MissingAmountReason.Unparseable);
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HttpClient_NoAmountInvoice_RefusedEvenOutsideAllowlist()
    {
        // The allowlist is enforced inside BudgetController.Check, so skipping
        // that call for a null amount disabled the allowlist as well — an
        // amountless invoice from ANY domain got paid.
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402(NoAmountInvoice));

        var mockWallet = CreatePayingWallet();
        var budget = new BudgetController(allowedDomains: new HashSet<string> { "trusted.example.com" });
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object, budget, new CredentialCache());

        var act = () => client.GetAsync("https://evil.example.com/paid-resource");

        await act.Should().ThrowAsync<InvoiceAmountUnknownException>();
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HttpClient_NoAmountInvoice_RefusedWithBudgetDisabled()
    {
        // An unknown amount is refused on its own merits: with no budget the
        // client still cannot tell the caller what it is about to spend.
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402(NoAmountInvoice));

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object, null, new CredentialCache());

        var act = () => client.GetAsync("https://example.com/paid-resource");

        await act.Should().ThrowAsync<InvoiceAmountUnknownException>();
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HttpClient_MppUnusableAmount_RefusesWithoutPaying()
    {
        // Zero-amount invoice plus an MPP amount MppAmountToSats cannot use
        // (negative). Nothing left to price the request with — refuse.
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402Mpp(NoAmountInvoice, "-100000"));

        var mockWallet = CreatePayingWallet();
        var budget = new BudgetController(maxSatsPerHour: 10_000);
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object, budget, new CredentialCache());

        var act = () => client.GetAsync("https://example.com/paid-resource");

        await act.Should().ThrowAsync<InvoiceAmountUnknownException>();
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        // The budget must not have gained headroom from a bogus negative spend.
        budget.SpentLastHour().Should().Be(0);
    }

    [Fact]
    public async Task HttpClient_WalletWithoutPreimage_RefusesBeforePaying()
    {
        // L402's retry needs the preimage to build the Authorization header, so
        // paying with an OpenNode-like wallet spends funds for no access.
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402("lnbc10u1ptest"));

        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.SupportsPreimage).Returns(false);
        mockWallet.Setup(w => w.Name).Returns("OpenNode");
        mockWallet.Setup(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);

        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object,
            new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        var act = () => client.GetAsync("https://example.com/paid-resource");

        await act.Should().ThrowAsync<UnsupportedWalletException>();
        // The whole point of failing fast: no payment was attempted.
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        client.SpendingLog.Count.Should().Be(0);
    }

    // ── L402DelegatingHandler ──
    //
    // Same logic, second surface. Previously untested, which is how it kept
    // both bugs after they were understood elsewhere.

    private static HttpClient BuildHandlerClient(
        MockHttpMessageHandler inner, IWallet wallet, BudgetController? budget,
        out L402DelegatingHandler l402Handler)
    {
        l402Handler = new L402DelegatingHandler(wallet, budget, new CredentialCache())
        {
            InnerHandler = inner,
        };
        return new HttpClient(l402Handler);
    }

    [Fact]
    public async Task DelegatingHandler_NoAmountInvoice_RefusesWithoutPaying()
    {
        var inner = new MockHttpMessageHandler();
        inner.EnqueueResponse(Create402(NoAmountInvoice));

        var mockWallet = CreatePayingWallet();
        var httpClient = BuildHandlerClient(
            inner, mockWallet.Object, new BudgetController(maxSatsPerRequest: 5000), out var l402Handler);

        var act = () => httpClient.GetAsync("https://example.com/paid-resource");

        var ex = await act.Should().ThrowAsync<InvoiceAmountUnknownException>();
        ex.Which.Reason.Should().Be(MissingAmountReason.NoAmountEncoded);
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        l402Handler.SpendingLog.Count.Should().Be(0);
    }

    [Fact]
    public async Task DelegatingHandler_UnparseableInvoice_RefusesWithoutPaying()
    {
        var inner = new MockHttpMessageHandler();
        inner.EnqueueResponse(Create402(UnparseableInvoice));

        var mockWallet = CreatePayingWallet();
        var httpClient = BuildHandlerClient(
            inner, mockWallet.Object, new BudgetController(maxSatsPerRequest: 5000), out _);

        var act = () => httpClient.GetAsync("https://example.com/paid-resource");

        var ex = await act.Should().ThrowAsync<InvoiceAmountUnknownException>();
        ex.Which.Reason.Should().Be(MissingAmountReason.Unparseable);
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DelegatingHandler_NoAmountInvoice_RefusedEvenOutsideAllowlist()
    {
        var inner = new MockHttpMessageHandler();
        inner.EnqueueResponse(Create402(NoAmountInvoice));

        var mockWallet = CreatePayingWallet();
        var budget = new BudgetController(allowedDomains: new HashSet<string> { "trusted.example.com" });
        var httpClient = BuildHandlerClient(inner, mockWallet.Object, budget, out _);

        var act = () => httpClient.GetAsync("https://evil.example.com/paid-resource");

        await act.Should().ThrowAsync<InvoiceAmountUnknownException>();
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DelegatingHandler_WalletWithoutPreimage_RefusesBeforePaying()
    {
        var inner = new MockHttpMessageHandler();
        inner.EnqueueResponse(Create402("lnbc10u1ptest"));

        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.SupportsPreimage).Returns(false);
        mockWallet.Setup(w => w.Name).Returns("OpenNode");
        mockWallet.Setup(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);

        var httpClient = BuildHandlerClient(
            inner, mockWallet.Object, new BudgetController(maxSatsPerRequest: 5000), out var l402Handler);

        var act = () => httpClient.GetAsync("https://example.com/paid-resource");

        await act.Should().ThrowAsync<UnsupportedWalletException>();
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        l402Handler.SpendingLog.Count.Should().Be(0);
    }

    // ── Still pays when the amount IS known ──

    [Fact]
    public async Task HttpClient_KnownAmount_StillPays()
    {
        var inner = new MockHttpMessageHandler();
        inner.EnqueueResponse(Create402("lnbc10u1ptest"));
        inner.EnqueueResponse(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("paid content"),
        });

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(inner), mockWallet.Object,
            new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        var response = await client.GetAsync("https://example.com/paid-resource");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        client.SpendingLog.TotalSpent().Should().Be(1_000);
    }
}
