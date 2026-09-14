using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using L402Requests.Wallets;
using NBitcoin.Secp256k1;

namespace L402Requests.Tests.Wallets;

/// <summary>Shared fixtures for the <see cref="IPaymentLookup"/> contract tests.</summary>
internal static class LookupFixtures
{
    // A 32-byte preimage and the payment hash it opens (SHA-256), computed rather than hand-typed.
    public static readonly string PreimageHex =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    public static readonly string PaymentHash =
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Convert.FromHexString(PreimageHex))).ToLowerInvariant();

    // Another valid-looking preimage that does NOT open PaymentHash.
    public const string WrongPreimageHex =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    public static readonly string[] InvalidHashes =
    {
        "",
        "abc",
        PaymentHashUpper(),
        "zz" + new string('0', 62),
        new string('0', 63),
        new string('0', 65),
    };

    private static string PaymentHashUpper() => PaymentHash.ToUpperInvariant();
}

public class PaymentLookupSupportTests
{
    [Fact]
    public void IsValidPaymentHash_AcceptsLowercase64Hex()
        => PaymentLookupSupport.IsValidPaymentHash(LookupFixtures.PaymentHash).Should().BeTrue();

    [Fact]
    public void IsValidPaymentHash_RejectsUppercaseShortLongAndNonHex()
    {
        foreach (var bad in LookupFixtures.InvalidHashes)
            PaymentLookupSupport.IsValidPaymentHash(bad).Should().BeFalse(bad);
        PaymentLookupSupport.IsValidPaymentHash(null).Should().BeFalse();
    }

    [Fact]
    public void PreimageOpensHash_TrueOnlyForTheRealPreimage()
    {
        PaymentLookupSupport.PreimageOpensHash(LookupFixtures.PreimageHex, LookupFixtures.PaymentHash).Should().BeTrue();
        PaymentLookupSupport.PreimageOpensHash(LookupFixtures.PreimageHex.ToUpperInvariant(), LookupFixtures.PaymentHash).Should().BeTrue();
        PaymentLookupSupport.PreimageOpensHash(LookupFixtures.WrongPreimageHex, LookupFixtures.PaymentHash).Should().BeFalse();
        PaymentLookupSupport.PreimageOpensHash(null, LookupFixtures.PaymentHash).Should().BeFalse();
        PaymentLookupSupport.PreimageOpensHash("not-hex", LookupFixtures.PaymentHash).Should().BeFalse();
    }
}

/// <summary>Scriptable LND handler: records the request and can either answer or throw at transport level.</summary>
internal sealed class ScriptedLndHandler : HttpMessageHandler
{
    public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
    public string ResponseBody { get; set; } = "";
    public Exception? Throw { get; set; }
    public string? LastPath { get; private set; }
    public int Calls { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Calls++;
        LastPath = request.RequestUri?.PathAndQuery;
        if (Throw is not null) throw Throw;
        return Task.FromResult(new HttpResponseMessage(StatusCode)
        {
            Content = new StringContent(ResponseBody, Encoding.UTF8, "application/json"),
        });
    }
}

public class LndWalletLookupTests
{
    private static (LndWallet Wallet, ScriptedLndHandler Handler) Make(string body, HttpStatusCode status = HttpStatusCode.OK, Exception? throws = null)
    {
        var handler = new ScriptedLndHandler { ResponseBody = body, StatusCode = status, Throw = throws };
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:8080") };
        return (new LndWallet(http), handler);
    }

    private static string Succeeded(string preimage, string? hash = null, string valueSat = "1500") =>
        "{\"result\":{\"payment_hash\":\"" + (hash ?? LookupFixtures.PaymentHash) + "\",\"value_sat\":\"" + valueSat +
        "\",\"status\":\"SUCCEEDED\",\"payment_preimage\":\"" + preimage + "\",\"failure_reason\":\"FAILURE_REASON_NONE\"}}";

    [Fact]
    public async Task Lookup_Succeeded_WithMatchingPreimage_IsPaid_AndCallsRouterTrackOnce()
    {
        var (wallet, handler) = Make(Succeeded(LookupFixtures.PreimageHex));

        var result = await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash);

        result.Status.Should().Be(PaymentLookupStatus.Paid);
        result.PreimageHex.Should().Be(LookupFixtures.PreimageHex);
        result.AmountSats.Should().Be(1500);
        handler.Calls.Should().Be(1);

        var expectedB64Url = Convert.ToBase64String(Convert.FromHexString(LookupFixtures.PaymentHash)).Replace('+', '-').Replace('/', '_');
        handler.LastPath.Should().StartWith("/v2/router/track/" + expectedB64Url);
    }

    [Fact]
    public async Task Lookup_Succeeded_WithBase64Preimage_IsPaid()
    {
        var b64 = Convert.ToBase64String(Convert.FromHexString(LookupFixtures.PreimageHex));
        var (wallet, _) = Make(Succeeded(b64));

        var result = await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash);

        result.Status.Should().Be(PaymentLookupStatus.Paid);
        result.PreimageHex.Should().Be(LookupFixtures.PreimageHex);
    }

    [Fact]
    public async Task Lookup_OnlyReadsFirstStreamLine_InFlightIsUnknown()
    {
        var body = "{\"result\":{\"status\":\"IN_FLIGHT\",\"payment_hash\":\"" + LookupFixtures.PaymentHash + "\"}}\n" +
                   Succeeded(LookupFixtures.PreimageHex);
        var (wallet, _) = Make(body);

        var result = await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash);

        result.Status.Should().Be(PaymentLookupStatus.Unknown, "an in-flight HTLC is not settled yet and we never wait for it");
    }

    [Fact]
    public async Task Lookup_Failed_IsNotPaid()
    {
        var (wallet, _) = Make("""{"result":{"status":"FAILED","failure_reason":"FAILURE_REASON_NO_ROUTE"}}""");
        (await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.NotPaid);
    }

    [Fact]
    public async Task Lookup_GrpcNotFound_IsNotPaid_OnBothHttp200AndHttp404()
    {
        const string notFound = """{"code":5,"message":"payment isn't initiated","details":[]}""";
        var (ok, _) = Make(notFound);
        (await ok.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.NotPaid);

        var (nf, _) = Make(notFound, HttpStatusCode.NotFound);
        (await nf.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.NotPaid);
    }

    [Fact]
    public async Task Lookup_OtherGrpcError_IsUnknown()
    {
        var (wallet, _) = Make("""{"code":16,"message":"permission denied"}""", HttpStatusCode.Unauthorized);
        (await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.Unknown);
    }

    [Fact]
    public async Task Lookup_TransportError_IsUnknown_NeverThrows()
    {
        var (wallet, _) = Make("", throws: new HttpRequestException("connection refused"));
        (await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.Unknown);

        var (timeout, _) = Make("", throws: new TaskCanceledException("request timed out"));
        (await timeout.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.Unknown);
    }

    [Fact]
    public async Task Lookup_GarbageBody_IsUnknown()
    {
        var (wallet, _) = Make("<html>not json</html>");
        (await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.Unknown);
    }

    [Fact]
    public async Task Lookup_PreimageMismatch_IsUnknown()
    {
        var (wallet, _) = Make(Succeeded(LookupFixtures.WrongPreimageHex));
        var result = await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash);
        result.Status.Should().Be(PaymentLookupStatus.Unknown);
        result.PreimageHex.Should().BeNull();
    }

    [Fact]
    public async Task Lookup_SucceededWithoutPreimage_IsUnknown()
    {
        var (wallet, _) = Make("{\"result\":{\"payment_hash\":\"" + LookupFixtures.PaymentHash + "\",\"status\":\"SUCCEEDED\"}}");
        (await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.Unknown);
    }

    [Fact]
    public async Task Lookup_ReplyForDifferentHash_IsUnknown()
    {
        var other = new string('a', 64);
        var (wallet, _) = Make(Succeeded(LookupFixtures.PreimageHex, hash: other));
        (await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.Unknown);
    }

    [Fact]
    public async Task Lookup_InvalidHash_ThrowsBeforeAnyCall()
    {
        var (wallet, handler) = Make(Succeeded(LookupFixtures.PreimageHex));
        foreach (var bad in LookupFixtures.InvalidHashes)
        {
            var act = () => wallet.LookupPaymentAsync(bad);
            await act.Should().ThrowAsync<ArgumentException>(bad);
        }
        handler.Calls.Should().Be(0);
    }
}

public class StrikeWalletLookupTests
{
    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") });
        }
    }

    [Fact]
    public async Task Lookup_IsUnknown_AndMakesNoHttpCall()
    {
        // Strike has no outgoing-payment lookup by hash; the adapter must say so honestly, not guess.
        var handler = new CountingHandler();
        var wallet = new StrikeWallet(new HttpClient(handler) { BaseAddress = new Uri("https://api.strike.me") });

        var result = await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash);

        result.Status.Should().Be(PaymentLookupStatus.Unknown);
        result.PreimageHex.Should().BeNull();
        handler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Lookup_InvalidHash_Throws()
    {
        var wallet = new StrikeWallet(new HttpClient(new CountingHandler()) { BaseAddress = new Uri("https://api.strike.me") });
        foreach (var bad in LookupFixtures.InvalidHashes)
        {
            var act = () => wallet.LookupPaymentAsync(bad);
            await act.Should().ThrowAsync<ArgumentException>(bad);
        }
    }

    [Fact]
    public void AllPreimageWallets_ImplementIPaymentLookup()
    {
        typeof(IPaymentLookup).IsAssignableFrom(typeof(LndWallet)).Should().BeTrue();
        typeof(IPaymentLookup).IsAssignableFrom(typeof(NwcWallet)).Should().BeTrue();
        typeof(IPaymentLookup).IsAssignableFrom(typeof(StrikeWallet)).Should().BeTrue();
        typeof(IPaymentLookup).IsAssignableFrom(typeof(OpenNodeWallet)).Should().BeFalse("OpenNode never surfaces preimages");
    }
}

public class NwcWalletLookupTests
{
    private static (ECPrivKey Priv, string PubHex) WalletKeys()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        bytes[0] = 0x01;
        ECPrivKey.TryCreate(bytes, out var priv);
        return (priv!, Convert.ToHexString(priv!.CreateXOnlyPubKey().ToBytes()).ToLowerInvariant());
    }

    private const string ClientSecretHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    private static NwcWallet Client(string relayUrl, string walletPubHex, double timeoutSeconds = 5) =>
        new($"nostr+walletconnect://{walletPubHex}?relay={relayUrl}&secret={ClientSecretHex}",
            TimeSpan.FromSeconds(timeoutSeconds), NwcEncryption.Nip04);

    private static string SettledReply(string preimage, string? type = "outgoing", long amountMsat = 21000) =>
        "{\"result_type\":\"lookup_invoice\",\"result\":{\"type\":\"" + type + "\",\"invoice\":\"lnbc...\",\"preimage\":\"" + preimage +
        "\",\"payment_hash\":\"" + LookupFixtures.PaymentHash + "\",\"amount\":" + amountMsat +
        ",\"fees_paid\":10,\"created_at\":1700000000,\"settled_at\":1700000010,\"state\":\"settled\"}}";

    private static async Task<(MockNwcRelay Relay, NwcWallet Wallet, string WalletPub)> Start(string? lookupPayload)
    {
        var (priv, pub) = WalletKeys();
        var relay = new MockNwcRelay(priv, pub, LookupFixtures.PreimageHex) { LookupResponsePayload = lookupPayload };
        await relay.StartAsync();
        return (relay, Client(relay.Url, pub), pub);
    }

    [Fact]
    public async Task Lookup_SettledOutgoingWithMatchingPreimage_IsPaid_AndSendsPaymentHashParam()
    {
        var (relay, wallet, _) = await Start(SettledReply(LookupFixtures.PreimageHex));
        await using (relay)
        {
            var result = await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash);

            result.Status.Should().Be(PaymentLookupStatus.Paid);
            result.PreimageHex.Should().Be(LookupFixtures.PreimageHex);
            result.AmountSats.Should().Be(21);
            relay.LastLookupParams!["payment_hash"]!.GetValue<string>().Should().Be(LookupFixtures.PaymentHash);
        }
    }

    [Fact]
    public async Task Lookup_NotFoundError_IsNotPaid()
    {
        var (relay, wallet, _) = await Start("""{"result_type":"lookup_invoice","error":{"code":"NOT_FOUND","message":"no such invoice"}}""");
        await using (relay)
            (await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.NotPaid);
    }

    [Fact]
    public async Task Lookup_OtherError_IsUnknown()
    {
        var (relay, wallet, _) = await Start("""{"result_type":"lookup_invoice","error":{"code":"INTERNAL","message":"boom"}}""");
        await using (relay)
            (await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.Unknown);
    }

    [Fact]
    public async Task Lookup_PreimageMismatch_IsUnknown()
    {
        var (relay, wallet, _) = await Start(SettledReply(LookupFixtures.WrongPreimageHex));
        await using (relay)
        {
            var result = await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash);
            result.Status.Should().Be(PaymentLookupStatus.Unknown);
            result.PreimageHex.Should().BeNull();
        }
    }

    [Fact]
    public async Task Lookup_UnreachableRelay_IsUnknown_NeverThrows()
    {
        var (_, pub) = WalletKeys();
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        var wallet = Client($"ws://127.0.0.1:{port}/", pub, timeoutSeconds: 2);

        (await wallet.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.Unknown);
    }

    [Fact]
    public async Task Lookup_WalletNeverReplies_IsUnknownAfterTimeout()
    {
        var (relay, _, pub) = await Start(lookupPayload: null); // wallet does not implement lookup_invoice
        await using (relay)
        {
            var w = Client(relay.Url, pub, timeoutSeconds: 1);
            (await w.LookupPaymentAsync(LookupFixtures.PaymentHash)).Status.Should().Be(PaymentLookupStatus.Unknown);
        }
    }

    [Fact]
    public async Task Lookup_InvalidHash_ThrowsBeforeConnecting()
    {
        var (_, pub) = WalletKeys();
        var wallet = Client("ws://127.0.0.1:1/", pub);
        foreach (var bad in LookupFixtures.InvalidHashes)
        {
            var act = () => wallet.LookupPaymentAsync(bad);
            await act.Should().ThrowAsync<ArgumentException>(bad);
        }
    }

    [Theory]
    [InlineData("""{"result":{"type":"incoming","preimage":"__P__","state":"settled"}}""", PaymentLookupStatus.Unknown)]
    [InlineData("""{"result":{"type":"outgoing","state":"pending"}}""", PaymentLookupStatus.Unknown)]
    [InlineData("""{"result":{"type":"outgoing","state":"failed"}}""", PaymentLookupStatus.NotPaid)]
    [InlineData("""{"result":{"type":"outgoing","state":"settled"}}""", PaymentLookupStatus.Paid)]
    [InlineData("""{"result":{"type":"outgoing","settled_at":1700000010,"amount":5000}}""", PaymentLookupStatus.Paid)]
    [InlineData("""{"result":{"type":"outgoing","payment_hash":"__OTHER__","preimage":"__P__"}}""", PaymentLookupStatus.Unknown)]
    [InlineData("""{"result_type":"lookup_invoice"}""", PaymentLookupStatus.Unknown)]
    [InlineData("""[]""", PaymentLookupStatus.Unknown)]
    public void ClassifyLookupReply_MapsStatesPerContract(string json, PaymentLookupStatus expected)
    {
        json = json.Replace("__P__", LookupFixtures.PreimageHex).Replace("__OTHER__", new string('b', 64));
        using var doc = JsonDocument.Parse(json);
        NwcWallet.ClassifyLookupReply(doc.RootElement, LookupFixtures.PaymentHash).Status.Should().Be(expected);
    }

    [Fact]
    public void ClassifyLookupReply_SettledWithoutPreimage_HasNoPreimageButAmount()
    {
        using var doc = JsonDocument.Parse("""{"result":{"type":"outgoing","state":"settled","amount":5000}}""");
        var r = NwcWallet.ClassifyLookupReply(doc.RootElement, LookupFixtures.PaymentHash);
        r.Status.Should().Be(PaymentLookupStatus.Paid);
        r.PreimageHex.Should().BeNull();
        r.AmountSats.Should().Be(5);
    }
}
