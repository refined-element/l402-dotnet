using System.Net;
using FluentAssertions;
using L402Requests.Wallets;
using Moq;

namespace L402Requests.Tests;

/// <summary>
/// Mock HttpMessageHandler that returns configured responses.
/// </summary>
internal class MockHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> _responses = new();
    public List<HttpRequestMessage> SentRequests { get; } = new();

    public void EnqueueResponse(HttpResponseMessage response)
    {
        _responses.Enqueue(response);
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        SentRequests.Add(request);
        if (_responses.Count == 0)
            throw new InvalidOperationException("No more mock responses configured");
        return Task.FromResult(_responses.Dequeue());
    }
}

public class L402HttpClientTests
{
    private const string TestMacaroon = "test_macaroon_abc123";
    private const string TestInvoice = "lnbc10u1ptest";
    private const string TestPreimage = "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567";

    private static HttpResponseMessage Create402Response()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.WwwAuthenticate.ParseAdd($"""L402 macaroon="{TestMacaroon}", invoice="{TestInvoice}" """);
        return response;
    }

    private static HttpResponseMessage Create200Response(string content = "success")
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(content),
        };
    }

    [Fact]
    public async Task GetAsync_200_PassesThrough()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create200Response());

        var httpClient = new HttpClient(handler);
        var mockWallet = new Mock<IWallet>();
        var client = new L402HttpClient(httpClient, mockWallet.Object, null, new CredentialCache());

        var response = await client.GetAsync("https://example.com/free-resource");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetAsync_402WithL402_PaysAndRetries()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402Response());
        handler.EnqueueResponse(Create200Response("paid content"));

        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.PayInvoiceAsync(TestInvoice, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);
        mockWallet.Setup(w => w.SupportsPreimage).Returns(true);
        mockWallet.Setup(w => w.Name).Returns("Mock");

        var httpClient = new HttpClient(handler);
        var budget = new BudgetController(maxSatsPerRequest: 5000);
        var client = new L402HttpClient(httpClient, mockWallet.Object, budget, new CredentialCache());

        var response = await client.GetAsync("https://example.com/paid-resource");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Be("paid content");

        // Should have sent two requests: initial + retry
        handler.SentRequests.Should().HaveCount(2);

        // Retry should have Authorization header
        var retryRequest = handler.SentRequests[1];
        retryRequest.Headers.GetValues("Authorization").First()
            .Should().Be($"L402 {TestMacaroon}:{TestPreimage}");
    }

    [Fact]
    public async Task GetAsync_402WithoutL402Header_PassesThrough()
    {
        var handler = new MockHttpMessageHandler();
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired)
        {
            Content = new StringContent("payment required but not L402"),
        };
        handler.EnqueueResponse(response);

        var mockWallet = new Mock<IWallet>();
        var httpClient = new HttpClient(handler);
        var client = new L402HttpClient(httpClient, mockWallet.Object, null, new CredentialCache());

        var result = await client.GetAsync("https://example.com/non-l402-paywall");

        result.StatusCode.Should().Be(HttpStatusCode.PaymentRequired);
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetAsync_BudgetExceeded_ThrowsBeforePayment()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402Response());

        var mockWallet = new Mock<IWallet>();
        var httpClient = new HttpClient(handler);
        var budget = new BudgetController(maxSatsPerRequest: 100); // Invoice is 1000 sats
        var client = new L402HttpClient(httpClient, mockWallet.Object, budget, new CredentialCache());

        var act = () => client.GetAsync("https://example.com/expensive-resource");

        await act.Should().ThrowAsync<BudgetExceededException>();
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetAsync_PaymentFails_ThrowsAndRecords()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402Response());

        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.PayInvoiceAsync(TestInvoice, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new PaymentFailedException("insufficient balance", TestInvoice));

        var httpClient = new HttpClient(handler);
        var budget = new BudgetController(maxSatsPerRequest: 5000);
        var client = new L402HttpClient(httpClient, mockWallet.Object, budget, new CredentialCache());

        var act = () => client.GetAsync("https://example.com/paid-resource");

        await act.Should().ThrowAsync<PaymentFailedException>();

        // Should record failed payment
        client.SpendingLog.Count.Should().Be(1);
        client.SpendingLog.Records[0].Success.Should().BeFalse();
    }

    [Fact]
    public async Task GetAsync_SuccessfulPayment_RecordsInSpendingLog()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402Response());
        handler.EnqueueResponse(Create200Response());

        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.PayInvoiceAsync(TestInvoice, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);

        var httpClient = new HttpClient(handler);
        var budget = new BudgetController(maxSatsPerRequest: 5000);
        var client = new L402HttpClient(httpClient, mockWallet.Object, budget, new CredentialCache());

        await client.GetAsync("https://example.com/paid-resource");

        client.SpendingLog.Count.Should().Be(1);
        client.SpendingLog.TotalSpent().Should().Be(1000);
        client.SpendingLog.Records[0].Success.Should().BeTrue();
        client.SpendingLog.Records[0].Domain.Should().Be("example.com");
        client.SpendingLog.Records[0].Preimage.Should().Be(TestPreimage);
    }

    [Fact]
    public async Task GetAsync_CachedCredential_SkipsPayment()
    {
        var handler = new MockHttpMessageHandler();
        // First request: 402 → pay → 200
        handler.EnqueueResponse(Create402Response());
        handler.EnqueueResponse(Create200Response("first response"));
        // Second request: 200 (uses cached credential)
        handler.EnqueueResponse(Create200Response("second response"));

        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.PayInvoiceAsync(TestInvoice, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);

        var httpClient = new HttpClient(handler);
        var client = new L402HttpClient(httpClient, mockWallet.Object, new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        // First request triggers payment
        await client.GetAsync("https://example.com/paid-resource");

        // Second request should use cached credential
        var response2 = await client.GetAsync("https://example.com/paid-resource");
        response2.StatusCode.Should().Be(HttpStatusCode.OK);

        // Wallet should only be called once
        mockWallet.Verify(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);

        // Third request should have the Authorization header (from cache)
        handler.SentRequests[2].Headers.GetValues("Authorization").First()
            .Should().Contain("L402");
    }

    [Fact]
    public async Task PostAsync_402_PaysAndRetries()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402Response());
        handler.EnqueueResponse(Create200Response("created"));

        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.PayInvoiceAsync(TestInvoice, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);

        var httpClient = new HttpClient(handler);
        var client = new L402HttpClient(httpClient, mockWallet.Object, new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        var content = new StringContent("{\"data\":\"test\"}");
        var response = await client.PostAsync("https://example.com/api/create", content);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        handler.SentRequests.Should().HaveCount(2);
    }

    [Fact]
    public async Task SpendingLog_ByDomain_GroupsCorrectly()
    {
        var handler = new MockHttpMessageHandler();
        // Two 402s for different domains
        handler.EnqueueResponse(Create402Response());
        handler.EnqueueResponse(Create200Response());

        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.PayInvoiceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);

        var httpClient = new HttpClient(handler);
        var client = new L402HttpClient(httpClient, mockWallet.Object, new BudgetController(maxSatsPerRequest: 5000), new CredentialCache());

        await client.GetAsync("https://example.com/paid-resource");

        var byDomain = client.SpendingLog.ByDomain();
        byDomain.Should().ContainKey("example.com");
        byDomain["example.com"].Should().Be(1000);
    }

    [Fact]
    public async Task GetAsync_NoBudget_StillWorks()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402Response());
        handler.EnqueueResponse(Create200Response());

        var mockWallet = new Mock<IWallet>();
        mockWallet.Setup(w => w.PayInvoiceAsync(TestInvoice, It.IsAny<CancellationToken>()))
            .ReturnsAsync(TestPreimage);

        var httpClient = new HttpClient(handler);
        // No budget controller
        var client = new L402HttpClient(httpClient, mockWallet.Object, null, new CredentialCache());

        var response = await client.GetAsync("https://example.com/paid-resource");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DeleteAsync_Works()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create200Response());

        var mockWallet = new Mock<IWallet>();
        var httpClient = new HttpClient(handler);
        var client = new L402HttpClient(httpClient, mockWallet.Object, null, new CredentialCache());

        var response = await client.DeleteAsync("https://example.com/resource/1");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        handler.SentRequests[0].Method.Should().Be(HttpMethod.Delete);
    }
}
