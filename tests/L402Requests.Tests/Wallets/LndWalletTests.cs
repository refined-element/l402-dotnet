using System.Net;
using System.Text;
using FluentAssertions;
using L402Requests.Wallets;

namespace L402Requests.Tests.Wallets;

internal class MockLndHandler : HttpMessageHandler
{
    public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
    public string? ResponseBody { get; set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromResult(new HttpResponseMessage(StatusCode)
        {
            Content = new StringContent(ResponseBody ?? "", Encoding.UTF8, "application/json"),
        });
    }
}

public class LndWalletTests
{
    [Fact]
    public async Task PayInvoiceAsync_Succeeded_ReturnsHexPreimage()
    {
        // Base64-encoded preimage that should be converted to hex
        var preimageBytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var preimageBase64 = Convert.ToBase64String(preimageBytes);

        var handler = new MockLndHandler
        {
            ResponseBody = "{\"result\": {\"status\": \"SUCCEEDED\", \"payment_preimage\": \"" + preimageBase64 + "\"}}",
        };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var preimage = await wallet.PayInvoiceAsync("lnbc10u1ptest");

        preimage.Should().Be("deadbeef");
    }

    [Fact]
    public async Task PayInvoiceAsync_AlreadyHex_ReturnsAsIs()
    {
        // Use a hex string that is NOT valid base64 (odd padding), so the fallback path is taken
        var hexPreimage = "0123456789abcdef0";  // Not valid base64 (length not multiple of 4, invalid chars)
        var handler = new MockLndHandler
        {
            ResponseBody = "{\"result\": {\"status\": \"SUCCEEDED\", \"payment_preimage\": \"" + hexPreimage + "\"}}",
        };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var preimage = await wallet.PayInvoiceAsync("lnbc10u1ptest");

        preimage.Should().Be(hexPreimage);
    }

    [Fact]
    public async Task PayInvoiceAsync_Failed_Throws()
    {
        var handler = new MockLndHandler
        {
            ResponseBody = """{"result": {"status": "FAILED", "failure_reason": "INSUFFICIENT_BALANCE"}}""",
        };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var act = () => wallet.PayInvoiceAsync("lnbc10u1ptest");

        await act.Should().ThrowAsync<PaymentFailedException>()
            .Where(e => e.Reason.Contains("INSUFFICIENT_BALANCE"));
    }

    [Fact]
    public async Task PayInvoiceAsync_HttpError_Throws()
    {
        var handler = new MockLndHandler { StatusCode = HttpStatusCode.InternalServerError, ResponseBody = "error" };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var act = () => wallet.PayInvoiceAsync("lnbc10u1ptest");

        await act.Should().ThrowAsync<PaymentFailedException>();
    }

    [Fact]
    public async Task PayInvoiceAsync_NoResponse_Throws()
    {
        var handler = new MockLndHandler { ResponseBody = "" };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var act = () => wallet.PayInvoiceAsync("lnbc10u1ptest");

        await act.Should().ThrowAsync<PaymentFailedException>()
            .Where(e => e.Reason.Contains("No response from LND"));
    }

    [Fact]
    public async Task PayInvoiceAsync_StreamingJson_ParsesLastLine()
    {
        var preimageBytes = new byte[] { 0xAB, 0xCD };
        var preimageBase64 = Convert.ToBase64String(preimageBytes);

        var handler = new MockLndHandler
        {
            ResponseBody = "{\"result\": {\"status\": \"IN_FLIGHT\"}}\n{\"result\": {\"status\": \"SUCCEEDED\", \"payment_preimage\": \"" + preimageBase64 + "\"}}",
        };

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        var wallet = new LndWallet(httpClient);

        var preimage = await wallet.PayInvoiceAsync("lnbc10u1ptest");

        preimage.Should().Be("abcd");
    }

    [Fact]
    public void Properties_Correct()
    {
        using var wallet = new LndWallet("https://localhost:8080", "deadbeef");
        wallet.Name.Should().Be("LND");
        wallet.SupportsPreimage.Should().BeTrue();
    }
}
