using System.Net;
using System.Reflection;
using FluentAssertions;
using L402Requests.Wallets;
using Moq;

namespace L402Requests.Tests;

/// <summary>
/// Every request the library issues carries <c>User-Agent: L402Requests/&lt;version&gt;</c>
/// unless the caller already set one (on the request or on the HttpClient they supplied).
/// Server-side analytics classify paid traffic by the <c>L402Requests</c> prefix.
/// </summary>
public class UserAgentTests
{
    private const string TestMacaroon = "test_macaroon_abc123";
    private const string TestInvoice = "lnbc10u1ptest";
    private const string TestPreimage = "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567";
    private const string CallerAgent = "caller-agent/9.9";

    private static HttpResponseMessage Create402()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.WwwAuthenticate.ParseAdd($"""L402 macaroon="{TestMacaroon}", invoice="{TestInvoice}" """);
        return response;
    }

    private static HttpResponseMessage Create200() => new(HttpStatusCode.OK) { Content = new StringContent("ok") };

    private static Mock<IWallet> PayingWallet()
    {
        var wallet = new Mock<IWallet>();
        wallet.Setup(w => w.PayInvoiceAsync(TestInvoice, It.IsAny<CancellationToken>())).ReturnsAsync(TestPreimage);
        wallet.Setup(w => w.SupportsPreimage).Returns(true);
        wallet.Setup(w => w.Name).Returns("Mock");
        return wallet;
    }

    private static string? UserAgentOf(HttpRequestMessage request)
        => request.Headers.TryGetValues("User-Agent", out var values) ? string.Join(" ", values) : null;

    // The package version as the assembly carries it, minus any "+commit" suffix.
    // Prerelease-safe: "0.12.0-beta" stays "0.12.0-beta".
    private static string ExpectedVersion()
    {
        var informational = typeof(L402HttpClient).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        var plus = informational.IndexOf('+');
        return plus >= 0 ? informational[..plus] : informational;
    }

    // ── Format / version ──

    [Fact]
    public void Value_IsProductTokenSlashPackageVersion()
    {
        UserAgent.Value.Should().Be($"L402Requests/{ExpectedVersion()}");
        UserAgent.Value.Should().StartWith("L402Requests/");
    }

    [Fact]
    public void Version_MatchesAssemblyInformationalVersionWithoutCommitSuffix()
    {
        UserAgent.Version.Should().Be(ExpectedVersion());
        UserAgent.Version.Should().NotContain("+");
    }

    [Theory]
    [InlineData("1.2.3+abcdef0123456789", "1.2.3")]
    [InlineData("1.2.3", "1.2.3")]
    [InlineData(" 1.2.3 ", "1.2.3")]
    [InlineData("0.12.0-beta+abcdef", "0.12.0-beta")]
    public void ResolveVersion_StripsSourceRevisionSuffix(string informational, string expected)
    {
        UserAgent.ResolveVersion(informational, new Version(9, 9, 9, 0)).Should().Be(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("+abcdef")]
    public void ResolveVersion_FallsBackToAssemblyVersion(string? informational)
    {
        UserAgent.ResolveVersion(informational, new Version(4, 5, 6, 0)).Should().Be("4.5.6");
    }

    // ── L402HttpClient ──

    [Fact]
    public async Task Client_FreeRequest_CarriesUserAgent()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create200());
        var client = new L402HttpClient(new HttpClient(handler), new Mock<IWallet>().Object, null, new CredentialCache());

        await client.GetAsync("https://example.com/free");

        UserAgentOf(handler.SentRequests[0]).Should().Be(UserAgent.Value);
    }

    [Fact]
    public async Task Client_402RequestAndPaidRetry_BothCarryUserAgent()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402());
        handler.EnqueueResponse(Create200());
        var client = new L402HttpClient(new HttpClient(handler), PayingWallet().Object, null, new CredentialCache());

        var response = await client.GetAsync("https://example.com/paid");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        handler.SentRequests.Should().HaveCount(2);
        UserAgentOf(handler.SentRequests[0]).Should().Be(UserAgent.Value);
        UserAgentOf(handler.SentRequests[1]).Should().Be(UserAgent.Value);
        handler.SentRequests[1].Headers.GetValues("Authorization").First()
            .Should().Be($"L402 {TestMacaroon}:{TestPreimage}");
    }

    [Fact]
    public async Task Client_CallerRequestUserAgent_Wins()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402());
        handler.EnqueueResponse(Create200());
        var client = new L402HttpClient(new HttpClient(handler), PayingWallet().Object, null, new CredentialCache());

        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/paid");
        request.Headers.TryAddWithoutValidation("User-Agent", CallerAgent);
        await client.SendAsync(request);

        UserAgentOf(handler.SentRequests[0]).Should().Be(CallerAgent);
        UserAgentOf(handler.SentRequests[1]).Should().Be(CallerAgent);
    }

    [Fact]
    public async Task Client_CallerHttpClientDefaultUserAgent_WinsAndClientIsNotMutated()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create402());
        handler.EnqueueResponse(Create200());
        var httpClient = new HttpClient(handler);
        httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", CallerAgent);
        var client = new L402HttpClient(httpClient, PayingWallet().Object, null, new CredentialCache());

        await client.GetAsync("https://example.com/paid");

        UserAgentOf(handler.SentRequests[0]).Should().Be(CallerAgent);
        UserAgentOf(handler.SentRequests[1]).Should().Be(CallerAgent);
        httpClient.DefaultRequestHeaders.GetValues("User-Agent").Should().Equal(CallerAgent);
    }

    [Fact]
    public async Task Client_CallerHttpClientWithoutUserAgent_IsNotMutated()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(Create200());
        var httpClient = new HttpClient(handler);
        var client = new L402HttpClient(httpClient, new Mock<IWallet>().Object, null, new CredentialCache());

        await client.GetAsync("https://example.com/free");

        UserAgentOf(handler.SentRequests[0]).Should().Be(UserAgent.Value);
        httpClient.DefaultRequestHeaders.Contains("User-Agent").Should().BeFalse();
    }

    // ── L402DelegatingHandler ──

    [Fact]
    public async Task Handler_402RequestAndPaidRetry_BothCarryUserAgent()
    {
        var inner = new MockHttpMessageHandler();
        inner.EnqueueResponse(Create402());
        inner.EnqueueResponse(Create200());
        var httpClient = new HttpClient(new L402DelegatingHandler(PayingWallet().Object) { InnerHandler = inner });

        var response = await httpClient.GetAsync("https://example.com/paid");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        inner.SentRequests.Should().HaveCount(2);
        UserAgentOf(inner.SentRequests[0]).Should().Be(UserAgent.Value);
        UserAgentOf(inner.SentRequests[1]).Should().Be(UserAgent.Value);
    }

    [Fact]
    public async Task Handler_CallerUserAgent_Wins()
    {
        var inner = new MockHttpMessageHandler();
        inner.EnqueueResponse(Create402());
        inner.EnqueueResponse(Create200());
        var httpClient = new HttpClient(new L402DelegatingHandler(PayingWallet().Object) { InnerHandler = inner });
        httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", CallerAgent);

        await httpClient.GetAsync("https://example.com/paid");

        UserAgentOf(inner.SentRequests[0]).Should().Be(CallerAgent);
        UserAgentOf(inner.SentRequests[1]).Should().Be(CallerAgent);
    }

    // ── Wallet HTTP clients the library constructs (and owns) itself ──
    // Each wallet's owned-client constructor runs over a mock handler; the outcome of the
    // call (a 500 here) is irrelevant — only the request that reached the wire is asserted.

    private static MockHttpMessageHandler ErroringHandler()
    {
        var handler = new MockHttpMessageHandler();
        handler.EnqueueResponse(new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent("{}"),
        });
        return handler;
    }

    [Fact]
    public async Task StrikeWallet_OwnedClient_SendsUserAgent()
    {
        var handler = ErroringHandler();
        using var wallet = new StrikeWallet("fixture-string-strike", "https://strike.example.com", handler);

        await Record.ExceptionAsync(() => wallet.PayInvoiceAsync(TestInvoice));

        handler.SentRequests.Should().NotBeEmpty();
        UserAgentOf(handler.SentRequests[0]).Should().Be(UserAgent.Value);
    }

    [Fact]
    public async Task OpenNodeWallet_OwnedClient_SendsUserAgent()
    {
        var handler = ErroringHandler();
        using var wallet = new OpenNodeWallet("fixture-string-opennode", "https://opennode.example.com", handler);

        await Record.ExceptionAsync(() => wallet.PayInvoiceAsync(TestInvoice));

        handler.SentRequests.Should().NotBeEmpty();
        UserAgentOf(handler.SentRequests[0]).Should().Be(UserAgent.Value);
    }

    [Fact]
    public async Task LndWallet_OwnedClient_SendsUserAgent()
    {
        var handler = ErroringHandler();
        using var wallet = new LndWallet("https://lnd.example.com:8080", "0201036c6e64", handler);

        await Record.ExceptionAsync(() => wallet.PayInvoiceAsync(TestInvoice));

        handler.SentRequests.Should().NotBeEmpty();
        UserAgentOf(handler.SentRequests[0]).Should().Be(UserAgent.Value);
    }
}
