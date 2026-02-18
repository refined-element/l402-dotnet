using System.Net;
using System.Text;
using FluentAssertions;
using L402Requests.Wallets;

namespace L402Requests.Tests.Wallets;

internal class MockStrikeHandler : HttpMessageHandler
{
    public string? LastRequestPath { get; private set; }
    public string? LastRequestBody { get; private set; }
    public HttpStatusCode QuoteStatusCode { get; set; } = HttpStatusCode.OK;
    public HttpStatusCode ExecuteStatusCode { get; set; } = HttpStatusCode.OK;
    public string QuoteId { get; set; } = "quote-123";
    public string? PreImage { get; set; } = "deadbeef";

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequestPath = request.RequestUri?.PathAndQuery;
        if (request.Content != null)
            LastRequestBody = await request.Content.ReadAsStringAsync(cancellationToken);

        // Payment quote creation
        if (request.Method == HttpMethod.Post && LastRequestPath?.Contains("payment-quotes/lightning") == true)
        {
            return new HttpResponseMessage(QuoteStatusCode)
            {
                Content = new StringContent(
                    $$"""{"paymentQuoteId": "{{QuoteId}}"}""",
                    Encoding.UTF8, "application/json"),
            };
        }

        // Payment execution
        if (request.Method == HttpMethod.Patch && LastRequestPath?.Contains("execute") == true)
        {
            var preimageJson = PreImage != null
                ? $$"""
                "lightning": {"preImage": "{{PreImage}}"},
                """
                : "";

            return new HttpResponseMessage(ExecuteStatusCode)
            {
                Content = new StringContent(
                    $$"""
                    {
                        "paymentId": "pay-123",
                        {{preimageJson}}
                        "state": "COMPLETED"
                    }
                    """,
                    Encoding.UTF8, "application/json"),
            };
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }
}

public class StrikeWalletTests
{
    [Fact]
    public async Task PayInvoiceAsync_QuoteAndExecute_ReturnsPreimage()
    {
        var handler = new MockStrikeHandler { PreImage = "test_preimage_hex" };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.strike.me") };
        httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer test-key");
        var wallet = new StrikeWallet(httpClient);

        var preimage = await wallet.PayInvoiceAsync("lnbc10u1ptest");

        preimage.Should().Be("test_preimage_hex");
    }

    [Fact]
    public async Task PayInvoiceAsync_QuoteFails_Throws()
    {
        var handler = new MockStrikeHandler { QuoteStatusCode = HttpStatusCode.BadRequest };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.strike.me") };
        httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer test-key");
        var wallet = new StrikeWallet(httpClient);

        var act = () => wallet.PayInvoiceAsync("lnbc10u1ptest");

        await act.Should().ThrowAsync<PaymentFailedException>()
            .Where(e => e.Reason.Contains("Strike quote failed"));
    }

    [Fact]
    public async Task PayInvoiceAsync_ExecuteFails_Throws()
    {
        var handler = new MockStrikeHandler { ExecuteStatusCode = HttpStatusCode.InternalServerError };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.strike.me") };
        httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer test-key");
        var wallet = new StrikeWallet(httpClient);

        var act = () => wallet.PayInvoiceAsync("lnbc10u1ptest");

        await act.Should().ThrowAsync<PaymentFailedException>()
            .Where(e => e.Reason.Contains("Strike execution failed"));
    }

    [Fact]
    public async Task PayInvoiceAsync_NoPreimage_Throws()
    {
        var handler = new MockStrikeHandler { PreImage = null };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.strike.me") };
        httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer test-key");
        var wallet = new StrikeWallet(httpClient);

        var act = () => wallet.PayInvoiceAsync("lnbc10u1ptest");

        await act.Should().ThrowAsync<PaymentFailedException>()
            .Where(e => e.Reason.Contains("no preimage returned"));
    }

    [Fact]
    public void Properties_Correct()
    {
        using var wallet = new StrikeWallet("test-key");
        wallet.Name.Should().Be("Strike");
        wallet.SupportsPreimage.Should().BeTrue();
    }

    [Fact]
    public async Task PayInvoiceAsync_UsesSourceCurrencyBtc()
    {
        var handler = new MockStrikeHandler { PreImage = "pre123" };
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.strike.me") };
        httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer test-key");
        var wallet = new StrikeWallet(httpClient);

        await wallet.PayInvoiceAsync("lnbc10u1ptest");

        handler.LastRequestBody.Should().Contain("BTC");
    }
}
