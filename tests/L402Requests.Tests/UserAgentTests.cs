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
    private const string Format = @"^L402Requests/\d+\.\d+\.\d+$";

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

    private static string ExpectedVersion()
        => typeof(L402HttpClient).Assembly.GetName().Version!.ToString(3);

    // ── Format / version ──

    [Fact]
    public void Value_HasProductTokenAndSemverVersion()
    {
        UserAgent.Value.Should().MatchRegex(Format);
        UserAgent.Value.Should().Be($"L402Requests/{ExpectedVersion()}");
    }

    [Fact]
    public void Version_MatchesAssemblyInformationalVersionWithoutCommitSuffix()
    {
        var informational = typeof(L402HttpClient).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        var plus = informational.IndexOf('+');
        var expected = plus >= 0 ? informational[..plus] : informational;

        UserAgent.Version.Should().Be(expected);
        UserAgent.Version.Should().NotContain("+");
    }

    [Theory]
    [InlineData("1.2.3+abcdef0123456789", "1.2.3")]
    [InlineData("1.2.3", "1.2.3")]
    [InlineData(" 1.2.3 ", "1.2.3")]
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

    private static string OwnedClientUserAgent(object wallet)
    {
        var client = (HttpClient)wallet.GetType()
            .GetField("_httpClient", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(wallet)!;
        return client.DefaultRequestHeaders.TryGetValues("User-Agent", out var values)
            ? string.Join(" ", values)
            : "";
    }

    [Fact]
    public void StrikeWallet_OwnedClient_CarriesUserAgent()
    {
        using var wallet = new StrikeWallet("fixture-string-strike");
        OwnedClientUserAgent(wallet).Should().Be(UserAgent.Value);
    }

    [Fact]
    public void OpenNodeWallet_OwnedClient_CarriesUserAgent()
    {
        using var wallet = new OpenNodeWallet("fixture-string-opennode");
        OwnedClientUserAgent(wallet).Should().Be(UserAgent.Value);
    }

    [Fact]
    public void LndWallet_OwnedClient_CarriesUserAgent()
    {
        using var wallet = new LndWallet("https://127.0.0.1:8080", "0201036c6e64");
        OwnedClientUserAgent(wallet).Should().Be(UserAgent.Value);
    }
}
