using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;

namespace L402Requests.Tests;

/// <summary>
/// Modern draft-00 Payment challenges (draft-httpauth-payment-00 +
/// draft-lightning-charge-00): parse, precedence, and credential build.
/// The legacy Payment profile (invoice= directly in the header) and classic
/// L402 stay on their existing code paths, unchanged.
/// </summary>
public class ModernPaymentChallengeTests
{
    private const string TestInvoice = "lnbc10u1ptest"; // 1000 sats
    private const string TestPaymentHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string TestPreimage = "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567";
    private const string FutureExpires = "2099-01-01T00:00:00Z";
    private const string PastExpires = "2020-01-01T00:00:00Z";

    private static string B64UrlNoPad(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string B64UrlPadded(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s))
            .Replace('+', '-').Replace('/', '_');

    private static byte[] B64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        var rem = padded.Length % 4;
        if (rem != 0)
            padded += new string('=', 4 - rem);
        return Convert.FromBase64String(padded);
    }

    private static string RequestJson(
        string invoice = TestInvoice, string amount = "1000", string? currency = "sat")
    {
        var currencyPart = currency is null ? "" : $"\"currency\":\"{currency}\",";
        return $"{{\"amount\":\"{amount}\",{currencyPart}\"methodDetails\":{{\"invoice\":\"{invoice}\",\"paymentHash\":\"{TestPaymentHash}\",\"network\":\"mainnet\"}}}}";
    }

    private static string ModernHeader(
        string request, string expires = FutureExpires, string extra = "")
        => $"Payment id=\"chg_fixture01\", realm=\"api.example.com\", method=\"lightning\", intent=\"charge\", request=\"{request}\", expires=\"{expires}\"{extra}";

    // ── Parse: happy path ──

    [Fact]
    public void Parse_ValidModernHeader_ReturnsChallenge()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var result = ModernPaymentChallenge.Parse(ModernHeader(encoded));

        result.Should().NotBeNull();
        result!.Id.Should().Be("chg_fixture01");
        result.Realm.Should().Be("api.example.com");
        result.Method.Should().Be("lightning");
        result.Intent.Should().Be("charge");
        result.Request.Should().Be(encoded); // byte-exact, as received
        result.Expires.Should().Be(FutureExpires);
        result.Invoice.Should().Be(TestInvoice);
        result.Amount.Should().Be("1000");
        result.Currency.Should().Be("sat");
        result.PaymentHash.Should().Be(TestPaymentHash);
        result.Network.Should().Be("mainnet");
        result.IsExpired.Should().BeFalse();
    }

    [Fact]
    public void Parse_OptionalParams_Captured()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var header = ModernHeader(encoded,
            extra: ", digest=\"sha-256=fixturedigest\", description=\"Coffee, black\", opaque=\"fixture-opaque\"");

        var result = ModernPaymentChallenge.Parse(header);

        result.Should().NotBeNull();
        result!.Digest.Should().Be("sha-256=fixturedigest");
        result.Description.Should().Be("Coffee, black"); // comma inside quotes preserved
        result.Opaque.Should().Be("fixture-opaque");
    }

    [Fact]
    public void Parse_WithoutOptionalParams_OptionalsNull()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var result = ModernPaymentChallenge.Parse(ModernHeader(encoded));

        result.Should().NotBeNull();
        result!.Digest.Should().BeNull();
        result.Description.Should().BeNull();
        result.Opaque.Should().BeNull();
    }

    [Fact]
    public void Parse_SupersetHeaderWithLegacyParams_ParsesAsModern()
    {
        // A server may send one header carrying BOTH the modern params and the
        // legacy invoice/amount/currency params. Unknown params are ignored;
        // the modern request wins.
        var encoded = B64UrlNoPad(RequestJson(invoice: TestInvoice));
        var header = ModernHeader(encoded,
            extra: $", invoice=\"lnbc_legacy_param\", amount=\"999\", currency=\"sat\"");

        var result = ModernPaymentChallenge.Parse(header);

        result.Should().NotBeNull();
        result!.Invoice.Should().Be(TestInvoice); // from request, not the legacy param
        result.Amount.Should().Be("1000");
    }

    [Fact]
    public void Parse_PaddedBase64Url_Accepted_RawStringPreserved()
    {
        var encoded = B64UrlPadded(RequestJson());
        encoded.Should().EndWith("="); // fixture must actually exercise padding

        var result = ModernPaymentChallenge.Parse(ModernHeader(encoded));

        result.Should().NotBeNull();
        result!.Invoice.Should().Be(TestInvoice);
        result.Request.Should().Be(encoded); // padded form preserved byte-exact
    }

    [Fact]
    public void Parse_ParamOrderIndependent()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var header = $"Payment request=\"{encoded}\", intent=\"charge\", expires=\"{FutureExpires}\", method=\"lightning\", realm=\"api.example.com\", id=\"chg_fixture01\"";

        var result = ModernPaymentChallenge.Parse(header);

        result.Should().NotBeNull();
        result!.Id.Should().Be("chg_fixture01");
        result.Invoice.Should().Be(TestInvoice);
    }

    [Fact]
    public void Parse_SchemeCaseInsensitive()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var header = "payment " + ModernHeader(encoded)["Payment ".Length..];

        ModernPaymentChallenge.Parse(header).Should().NotBeNull();
    }

    [Fact]
    public void Parse_MissingExpires_StillParses()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var header = $"Payment id=\"chg_fixture01\", realm=\"api.example.com\", method=\"lightning\", intent=\"charge\", request=\"{encoded}\"";

        var result = ModernPaymentChallenge.Parse(header);

        result.Should().NotBeNull();
        result!.Expires.Should().BeNull();
        result.IsExpired.Should().BeFalse();
    }

    // ── Parse: rejection ──

    [Fact]
    public void Parse_NullOrEmpty_ReturnsNull()
    {
        ModernPaymentChallenge.Parse(null).Should().BeNull();
        ModernPaymentChallenge.Parse("").Should().BeNull();
        ModernPaymentChallenge.Parse("  ").Should().BeNull();
    }

    [Fact]
    public void Parse_NotPaymentScheme_ReturnsNull()
    {
        var encoded = B64UrlNoPad(RequestJson());
        ModernPaymentChallenge.Parse($"Bearer request=\"{encoded}\"").Should().BeNull();
        ModernPaymentChallenge.Parse($"L402 macaroon=\"abc\", invoice=\"{TestInvoice}\"").Should().BeNull();
    }

    [Fact]
    public void Parse_NoRequestParam_ReturnsNull()
    {
        // A Payment header without request= is the legacy profile, not modern.
        var header = $"Payment realm=\"api.example.com\", method=\"lightning\", invoice=\"{TestInvoice}\", amount=\"1000\"";
        ModernPaymentChallenge.Parse(header).Should().BeNull();
    }

    [Fact]
    public void Parse_BadBase64Request_ReturnsNull()
    {
        ModernPaymentChallenge.Parse(ModernHeader("!!!not-base64url!!!")).Should().BeNull();
    }

    [Fact]
    public void Parse_BadJsonRequest_ReturnsNull()
    {
        ModernPaymentChallenge.Parse(ModernHeader(B64UrlNoPad("not json at all"))).Should().BeNull();
    }

    [Fact]
    public void Parse_RequestMissingInvoice_ReturnsNull()
    {
        var json = "{\"amount\":\"1000\",\"currency\":\"sat\",\"methodDetails\":{\"network\":\"mainnet\"}}";
        ModernPaymentChallenge.Parse(ModernHeader(B64UrlNoPad(json))).Should().BeNull();
    }

    [Fact]
    public void Parse_NonLightningMethod_ReturnsNull()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var header = $"Payment id=\"chg_fixture01\", realm=\"api.example.com\", method=\"card\", intent=\"charge\", request=\"{encoded}\", expires=\"{FutureExpires}\"";
        ModernPaymentChallenge.Parse(header).Should().BeNull();
    }

    [Fact]
    public void Parse_NonChargeIntent_ReturnsNull()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var header = $"Payment id=\"chg_fixture01\", realm=\"api.example.com\", method=\"lightning\", intent=\"authorize\", request=\"{encoded}\", expires=\"{FutureExpires}\"";
        ModernPaymentChallenge.Parse(header).Should().BeNull();
    }

    [Fact]
    public void Parse_NonSatCurrency_ReturnsNull()
    {
        var encoded = B64UrlNoPad(RequestJson(currency: "usd"));
        ModernPaymentChallenge.Parse(ModernHeader(encoded)).Should().BeNull();
    }

    [Fact]
    public void Parse_MissingCurrency_StillParses()
    {
        var encoded = B64UrlNoPad(RequestJson(currency: null));
        var result = ModernPaymentChallenge.Parse(ModernHeader(encoded));
        result.Should().NotBeNull();
        result!.Currency.Should().BeNull();
    }

    [Fact]
    public void Parse_ExpiredChallenge_ParsesWithIsExpiredTrue()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var result = ModernPaymentChallenge.Parse(ModernHeader(encoded, expires: PastExpires));

        result.Should().NotBeNull();
        result!.IsExpired.Should().BeTrue();
    }

    [Fact]
    public void ModernPaymentChallenge_ImplementsIPaymentChallenge()
    {
        var encoded = B64UrlNoPad(RequestJson());
        IPaymentChallenge? challenge = ModernPaymentChallenge.Parse(ModernHeader(encoded));
        challenge.Should().NotBeNull();
        challenge!.Invoice.Should().Be(TestInvoice);
    }

    // ── Precedence via TryParsePaymentChallenge ──

    [Fact]
    public void TryParsePaymentChallenge_ModernOnly_ReturnsModern()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate", ModernHeader(B64UrlNoPad(RequestJson())));

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeOfType<ModernPaymentChallenge>();
        challenge!.Invoice.Should().Be(TestInvoice);
    }

    [Fact]
    public void TryParsePaymentChallenge_ModernAndLegacySeparateHeaders_PrefersModern()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            "Payment realm=\"api.example.com\", method=\"lightning\", invoice=\"lnbc_legacy_only\", amount=\"200\", currency=\"sat\"");
        response.Headers.TryAddWithoutValidation("WWW-Authenticate", ModernHeader(B64UrlNoPad(RequestJson())));

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeOfType<ModernPaymentChallenge>();
        challenge!.Invoice.Should().Be(TestInvoice);
    }

    [Fact]
    public void TryParsePaymentChallenge_SupersetHeader_PrefersModern()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            ModernHeader(B64UrlNoPad(RequestJson()), extra: ", invoice=\"lnbc_legacy_param\", amount=\"999\", currency=\"sat\""));

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeOfType<ModernPaymentChallenge>();
        challenge!.Invoice.Should().Be(TestInvoice);
    }

    [Fact]
    public void TryParsePaymentChallenge_L402AndModern_PrefersL402()
    {
        // The existing L402-over-Payment preference is unchanged.
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.WwwAuthenticate.ParseAdd("L402 macaroon=\"mac123\", invoice=\"lnbc10u1ptest\"");
        response.Headers.TryAddWithoutValidation("WWW-Authenticate", ModernHeader(B64UrlNoPad(RequestJson())));

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeOfType<L402Challenge>();
    }

    [Fact]
    public void TryParsePaymentChallenge_MalformedModernWithLegacyInvoiceSameHeader_FallsBackToLegacy()
    {
        // Superset case: the modern request param is broken, but the SAME header
        // carries legacy invoice= — the legacy params are an intentional fallback.
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            $"Payment id=\"chg_fixture02\", method=\"lightning\", intent=\"charge\", request=\"!!!not-base64url!!!\", invoice=\"{TestInvoice}\", amount=\"1000\", currency=\"sat\"");

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeOfType<MppChallenge>();
        challenge!.Invoice.Should().Be(TestInvoice);
    }

    [Fact]
    public void TryParsePaymentChallenge_MalformedModernWithoutLegacyInvoice_ReturnsNull()
    {
        // A malformed modern challenge with no legacy fallback in the header must
        // NOT be silently retried as legacy — nothing to pay here.
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            "Payment id=\"chg_fixture02\", method=\"lightning\", intent=\"charge\", request=\"!!!not-base64url!!!\"");

        L402Challenge.TryParsePaymentChallenge(response).Should().BeNull();
    }

    [Fact]
    public void TryParsePaymentChallenge_LegacyOnly_StillWorks()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            "Payment realm=\"api.example.com\", method=\"lightning\", invoice=\"lnbc200n1pmpp\", amount=\"200\", currency=\"sat\"");

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeOfType<MppChallenge>();
        challenge!.Invoice.Should().Be("lnbc200n1pmpp");
    }

    [Fact]
    public void TryParsePaymentChallenge_MultipleChallengesInOneHeader_SplitAndModernFound()
    {
        // Two challenges in a single WWW-Authenticate header value; the framework
        // splits them into separate AuthenticationHeaderValue entries.
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            $"Bearer realm=\"api\", {ModernHeader(B64UrlNoPad(RequestJson()))}");

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeOfType<ModernPaymentChallenge>();
        challenge!.Invoice.Should().Be(TestInvoice);
    }

    [Fact]
    public void TryParsePaymentChallenge_L402AndModernInOneHeader_PrefersL402()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            $"L402 macaroon=\"mac123\", invoice=\"lnbc10u1ptest\", {ModernHeader(B64UrlNoPad(RequestJson()))}");

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeOfType<L402Challenge>();
        ((L402Challenge)challenge!).Macaroon.Should().Be("mac123");
    }

    // ── Credential build ──

    [Fact]
    public void BuildAuthorizationHeader_PaymentSchemeWithBase64UrlNoPadding()
    {
        var challenge = ModernPaymentChallenge.Parse(ModernHeader(B64UrlNoPad(RequestJson())))!;

        var auth = challenge.BuildAuthorizationHeader(TestPreimage);

        auth.Should().StartWith("Payment ");
        var token = auth["Payment ".Length..];
        token.Should().NotBeEmpty();
        token.Should().NotContain("=");
        token.Should().NotContain("+");
        token.Should().NotContain("/");
    }

    [Fact]
    public void BuildAuthorizationHeader_EchoesChallengeByteExact()
    {
        var encoded = B64UrlNoPad(RequestJson());
        var challenge = ModernPaymentChallenge.Parse(ModernHeader(encoded))!;

        var auth = challenge.BuildAuthorizationHeader(TestPreimage);

        using var doc = JsonDocument.Parse(B64UrlDecode(auth["Payment ".Length..]));
        var challengeObj = doc.RootElement.GetProperty("challenge");
        challengeObj.GetProperty("id").GetString().Should().Be("chg_fixture01");
        challengeObj.GetProperty("realm").GetString().Should().Be("api.example.com");
        challengeObj.GetProperty("method").GetString().Should().Be("lightning");
        challengeObj.GetProperty("intent").GetString().Should().Be("charge");
        challengeObj.GetProperty("request").GetString().Should().Be(encoded); // never re-encoded
        challengeObj.GetProperty("expires").GetString().Should().Be(FutureExpires);
        doc.RootElement.GetProperty("payload").GetProperty("preimage").GetString().Should().Be(TestPreimage);
    }

    [Fact]
    public void BuildAuthorizationHeader_PaddedRequest_EchoedWithPadding()
    {
        var encoded = B64UrlPadded(RequestJson());
        var challenge = ModernPaymentChallenge.Parse(ModernHeader(encoded))!;

        var auth = challenge.BuildAuthorizationHeader(TestPreimage);

        using var doc = JsonDocument.Parse(B64UrlDecode(auth["Payment ".Length..]));
        doc.RootElement.GetProperty("challenge").GetProperty("request").GetString()
            .Should().Be(encoded); // received padded → echoed padded
    }

    [Fact]
    public void BuildAuthorizationHeader_UppercasePreimage_Lowercased()
    {
        var challenge = ModernPaymentChallenge.Parse(ModernHeader(B64UrlNoPad(RequestJson())))!;

        var auth = challenge.BuildAuthorizationHeader(TestPreimage.ToUpperInvariant());

        using var doc = JsonDocument.Parse(B64UrlDecode(auth["Payment ".Length..]));
        doc.RootElement.GetProperty("payload").GetProperty("preimage").GetString()
            .Should().Be(TestPreimage);
    }

    [Fact]
    public void BuildAuthorizationHeader_OptionalParamsEchoedWhenPresent()
    {
        var header = ModernHeader(B64UrlNoPad(RequestJson()),
            extra: ", digest=\"sha-256=fixturedigest\", description=\"Coffee, black\", opaque=\"fixture-opaque\"");
        var challenge = ModernPaymentChallenge.Parse(header)!;

        var auth = challenge.BuildAuthorizationHeader(TestPreimage);

        using var doc = JsonDocument.Parse(B64UrlDecode(auth["Payment ".Length..]));
        var challengeObj = doc.RootElement.GetProperty("challenge");
        challengeObj.GetProperty("digest").GetString().Should().Be("sha-256=fixturedigest");
        challengeObj.GetProperty("description").GetString().Should().Be("Coffee, black");
        challengeObj.GetProperty("opaque").GetString().Should().Be("fixture-opaque");
    }

    [Fact]
    public void BuildAuthorizationHeader_AbsentOptionalsOmitted_LegacyExtrasNeverEchoed()
    {
        // Superset header: legacy invoice/amount/currency are unknown params from
        // the modern challenge's point of view — they must not be echoed.
        var header = ModernHeader(B64UrlNoPad(RequestJson()),
            extra: ", invoice=\"lnbc_legacy_param\", amount=\"999\", currency=\"sat\"");
        var challenge = ModernPaymentChallenge.Parse(header)!;

        var auth = challenge.BuildAuthorizationHeader(TestPreimage);

        using var doc = JsonDocument.Parse(B64UrlDecode(auth["Payment ".Length..]));
        var challengeObj = doc.RootElement.GetProperty("challenge");
        challengeObj.TryGetProperty("digest", out _).Should().BeFalse();
        challengeObj.TryGetProperty("description", out _).Should().BeFalse();
        challengeObj.TryGetProperty("opaque", out _).Should().BeFalse();
        challengeObj.TryGetProperty("invoice", out _).Should().BeFalse();
        challengeObj.TryGetProperty("amount", out _).Should().BeFalse();
        challengeObj.TryGetProperty("currency", out _).Should().BeFalse();
    }
}
