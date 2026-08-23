using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using L402Requests.Wallets;
using Moq;

namespace L402Requests.Tests;

/// <summary>
/// End-to-end 402 flow for modern draft-00 Payment challenges, on both payment
/// surfaces (L402HttpClient and L402DelegatingHandler): pay → retry with the
/// modern credential → surface the Payment-Receipt. Modern credentials are
/// single-use server-side and must never be served from the credential cache.
/// </summary>
public class ModernPaymentFlowTests
{
    private const string TestInvoice = "lnbc10u1ptest"; // 1000 sats
    private const string NoAmountInvoice = "lnbc1ptest"; // no amount encoded
    private const string TestMacaroon = "test_macaroon_abc123";
    private const string TestPreimage = "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567";
    private const string TestPaymentHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string FutureExpires = "2099-01-01T00:00:00Z";
    private const string PastExpires = "2020-01-01T00:00:00Z";

    private static string B64UrlNoPad(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] B64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        var rem = padded.Length % 4;
        if (rem != 0)
            padded += new string('=', 4 - rem);
        return Convert.FromBase64String(padded);
    }

    private static string RequestJson(string invoice = TestInvoice, string amount = "1000") =>
        $"{{\"amount\":\"{amount}\",\"currency\":\"sat\",\"methodDetails\":{{\"invoice\":\"{invoice}\",\"paymentHash\":\"{TestPaymentHash}\",\"network\":\"mainnet\"}}}}";

    private static string ModernHeader(string encodedRequest, string expires = FutureExpires) =>
        $"Payment id=\"chg_fixture01\", realm=\"api.example.com\", method=\"lightning\", intent=\"charge\", request=\"{encodedRequest}\", expires=\"{expires}\"";

    private static HttpResponseMessage CreateModern402(
        string invoice = TestInvoice, string amount = "1000", string expires = FutureExpires)
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation(
            "WWW-Authenticate", ModernHeader(B64UrlNoPad(RequestJson(invoice, amount)), expires));
        return response;
    }

    private static HttpResponseMessage Create200(string content = "success", string? receiptHeader = null)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(content),
        };
        if (receiptHeader is not null)
            response.Headers.TryAddWithoutValidation("Payment-Receipt", receiptHeader);
        return response;
    }

    private static string ReceiptHeader(string status = "settled") =>
        B64UrlNoPad($"{{\"challengeId\":\"chg_fixture01\",\"method\":\"lightning\",\"reference\":\"{TestPaymentHash}\",\"status\":\"{status}\",\"timestamp\":\"2026-08-23T00:00:00Z\"}}");

    private static Mock<IWallet> CreatePayingWallet(string invoice = TestInvoice)
    {
        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.SupportsPreimage).Returns(true);
        mockWallet.Setup(w => w.Name).Returns("Mock");
        mockWallet.Setup(w => w.PayInvoiceAsync(invoice, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);
        return mockWallet;
    }

    private static JsonDocument DecodeModernCredential(string authorizationHeader)
    {
        authorizationHeader.Should().StartWith("Payment ");
        return JsonDocument.Parse(B64UrlDecode(authorizationHeader["Payment ".Length..]));
    }

    // ── L402HttpClient ──

    [Fact]
    public async Task GetAsync_Modern402_PaysAndRetriesWithModernCredential()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(CreateModern402());
        handler.EnqueueResponse(Create200("paid modern"));

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object,
            new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        var response = await client.GetAsync("https://example.com/paid-resource");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Be("paid modern");
        handler.SentRequests.Should().HaveCount(2);

        // The retry carries the modern credential, not the legacy Payment format
        // and not an L402 token.
        var auth = handler.SentRequests[1].Headers.GetValues("Authorization").First();
        auth.Should().NotContain("preimage=\"");
        auth.Should().NotContain("L402");
        using var doc = DecodeModernCredential(auth);
        var challengeObj = doc.RootElement.GetProperty("challenge");
        challengeObj.GetProperty("id").GetString().Should().Be("chg_fixture01");
        challengeObj.GetProperty("request").GetString().Should().Be(B64UrlNoPad(RequestJson()));
        doc.RootElement.GetProperty("payload").GetProperty("preimage").GetString().Should().Be(TestPreimage);
    }

    [Fact]
    public async Task GetAsync_Modern402_AcceptPaymentHeaderOnInitialRequest()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create200());

        var client = new L402HttpClient(
            new HttpClient(handler), new Mock<IWallet>().Object, null, new CredentialCache());

        await client.GetAsync("https://example.com/resource");

        handler.SentRequests[0].Headers.TryGetValues("Accept-Payment", out var values).Should().BeTrue();
        values!.First().Should().Be("lightning/charge");
    }

    [Fact]
    public async Task GetAsync_ExpiredModernChallenge_RefusesBeforePayment()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(CreateModern402(expires: PastExpires));

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object,
            new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        var act = () => client.GetAsync("https://example.com/paid-resource");

        await act.Should().ThrowAsync<ChallengeExpiredException>();
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        client.SpendingLog.Count.Should().Be(0);
    }

    [Fact]
    public async Task GetAsync_Modern402_ReceiptExposedInSpendingLog()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(CreateModern402());
        handler.EnqueueResponse(Create200(receiptHeader: ReceiptHeader()));

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object, null, new CredentialCache());

        var response = await client.GetAsync("https://example.com/paid-resource");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        client.SpendingLog.Count.Should().Be(1);
        var record = client.SpendingLog.Records[0];
        record.Success.Should().BeTrue();
        record.Receipt.Should().NotBeNull();
        record.Receipt!.ChallengeId.Should().Be("chg_fixture01");
        record.Receipt.Reference.Should().Be(TestPaymentHash);
        record.Receipt.Status.Should().Be("settled");
    }

    [Fact]
    public async Task GetAsync_Modern402_MalformedReceipt_DoesNotFailThePayment()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(CreateModern402());
        handler.EnqueueResponse(Create200(receiptHeader: "!!!not-base64!!!"));

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object, null, new CredentialCache());

        var response = await client.GetAsync("https://example.com/paid-resource");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        client.SpendingLog.Records[0].Success.Should().BeTrue();
        client.SpendingLog.Records[0].Receipt.Should().BeNull();
    }

    [Fact]
    public async Task GetAsync_ModernCredential_SingleUse_NotServedFromCache()
    {
        var handler = new MockHttpMessageHandler();
        // First request: modern 402 → pay → 200
        handler.EnqueueResponse(CreateModern402());
        handler.EnqueueResponse(Create200("first"));
        // Second request must NOT reuse the credential: fresh 402 → pay again → 200
        handler.EnqueueResponse(CreateModern402());
        handler.EnqueueResponse(Create200("second"));

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object, null, new CredentialCache());

        await client.GetAsync("https://example.com/paid-resource");
        var response2 = await client.GetAsync("https://example.com/paid-resource");

        response2.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response2.Content.ReadAsStringAsync()).Should().Be("second");

        // Paid twice — the modern credential is single-use server-side.
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
        handler.SentRequests.Should().HaveCount(4);
        // The second initial request carries no replayed Authorization header.
        handler.SentRequests[2].Headers.Contains("Authorization").Should().BeFalse();
    }

    [Fact]
    public async Task GetAsync_Modern402_L402CachingUnchanged()
    {
        // An L402 challenge answered earlier is still cached and replayed —
        // only modern credentials are excluded from reuse.
        var handler = new MockHttpMessageHandler();
        var l402Response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        l402Response.Headers.TryAddWithoutValidation(
            "WWW-Authenticate", $"L402 macaroon=\"{TestMacaroon}\", invoice=\"{TestInvoice}\"");
        handler.EnqueueResponse(l402Response);
        handler.EnqueueResponse(Create200("first"));
        handler.EnqueueResponse(Create200("second"));

        var mockWallet = CreatePayingWallet();
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object, null, new CredentialCache());

        await client.GetAsync("https://example.com/paid-resource");
        await client.GetAsync("https://example.com/paid-resource");

        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
        handler.SentRequests[2].Headers.GetValues("Authorization").First().Should().StartWith("L402 ");
    }

    [Fact]
    public async Task GetAsync_ModernNoAmountInvoice_FallsBackToRequestAmount()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(CreateModern402(invoice: NoAmountInvoice, amount: "500"));
        handler.EnqueueResponse(Create200());

        var mockWallet = CreatePayingWallet(NoAmountInvoice);
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object,
            new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        await client.GetAsync("https://example.com/paid-resource");

        client.SpendingLog.Count.Should().Be(1);
        client.SpendingLog.TotalSpent().Should().Be(500);
        client.SpendingLog.Records[0].AmountSats.Should().Be(500);
        // Modern challenges carry no macaroon — recorded as empty string.
        client.SpendingLog.Records[0].Macaroon.Should().Be("");
    }

    [Fact]
    public async Task GetAsync_ModernNoAmountInvoice_BudgetEnforcedViaRequestAmount()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(CreateModern402(invoice: NoAmountInvoice, amount: "2000"));

        var mockWallet = CreatePayingWallet(NoAmountInvoice);
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object,
            new BudgetController(maxSatsPerRequest: 1000), new CredentialCache());

        var act = () => client.GetAsync("https://example.com/expensive-resource");

        await act.Should().ThrowAsync<BudgetExceededException>();
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetAsync_L402AndModern402_PrefersL402()
    {
        var handler = new MockHttpMessageHandler();
        var response402 = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response402.Headers.TryAddWithoutValidation(
            "WWW-Authenticate", $"L402 macaroon=\"{TestMacaroon}\", invoice=\"{TestInvoice}\"");
        response402.Headers.TryAddWithoutValidation(
            "WWW-Authenticate", ModernHeader(B64UrlNoPad(RequestJson(invoice: "lnbc20u1pother", amount: "2000"))));
        handler.EnqueueResponse(response402);
        handler.EnqueueResponse(Create200());

        var mockWallet = CreatePayingWallet(); // only pays TestInvoice (the L402 one)
        var client = new L402HttpClient(
            new HttpClient(handler), mockWallet.Object, null, new CredentialCache());

        var response = await client.GetAsync("https://example.com/paid-resource");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        mockWallet.Verify(w => w.PayInvoiceAsync(TestInvoice, It.IsAny<CancellationToken>()), Times.Once);
        handler.SentRequests[1].Headers.GetValues("Authorization").First()
            .Should().Be($"L402 {TestMacaroon}:{TestPreimage}");
    }

    // ── L402DelegatingHandler ──

    [Fact]
    public async Task Handler_Modern402_PaysRetriesAndSurfacesReceipt_SingleUse()
    {
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.EnqueueResponse(CreateModern402());
        mockHandler.EnqueueResponse(Create200("first", receiptHeader: ReceiptHeader()));
        mockHandler.EnqueueResponse(CreateModern402());
        mockHandler.EnqueueResponse(Create200("second"));

        var mockWallet = CreatePayingWallet();
        var l402Handler = new L402DelegatingHandler(mockWallet.Object)
        {
            InnerHandler = mockHandler,
        };
        var httpClient = new HttpClient(l402Handler);

        var response1 = await httpClient.GetAsync("https://example.com/paid-resource");
        var response2 = await httpClient.GetAsync("https://example.com/paid-resource");

        response1.StatusCode.Should().Be(HttpStatusCode.OK);
        response2.StatusCode.Should().Be(HttpStatusCode.OK);

        // Modern credential on the retry
        var auth = mockHandler.SentRequests[1].Headers.GetValues("Authorization").First();
        using var doc = DecodeModernCredential(auth);
        doc.RootElement.GetProperty("payload").GetProperty("preimage").GetString().Should().Be(TestPreimage);

        // Receipt surfaced in the handler's spending log
        l402Handler.SpendingLog.Records[0].Receipt.Should().NotBeNull();
        l402Handler.SpendingLog.Records[0].Receipt!.Reference.Should().Be(TestPaymentHash);

        // Single-use: paid twice, no replayed Authorization on the second initial request
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
        mockHandler.SentRequests[2].Headers.Contains("Authorization").Should().BeFalse();
    }

    [Fact]
    public async Task Handler_ExpiredModernChallenge_RefusesBeforePayment()
    {
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.EnqueueResponse(CreateModern402(expires: PastExpires));

        var mockWallet = CreatePayingWallet();
        var l402Handler = new L402DelegatingHandler(mockWallet.Object)
        {
            InnerHandler = mockHandler,
        };
        var httpClient = new HttpClient(l402Handler);

        var act = () => httpClient.GetAsync("https://example.com/paid-resource");

        await act.Should().ThrowAsync<ChallengeExpiredException>();
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
