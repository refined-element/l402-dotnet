using FluentAssertions;
using System.Net;

namespace L402Requests.Tests;

public class L402ChallengeTests
{
    [Fact]
    public void Parse_QuotedValues_Succeeds()
    {
        var header = "L402 macaroon=\"abc123\", invoice=\"lnbc10u1ptest\"";
        var challenge = L402Challenge.Parse(header);
        challenge.Macaroon.Should().Be("abc123");
        challenge.Invoice.Should().Be("lnbc10u1ptest");
    }

    [Fact]
    public void Parse_UnquotedValues_Succeeds()
    {
        var header = "L402 macaroon=abc123, invoice=lnbc10u1ptest";
        var challenge = L402Challenge.Parse(header);
        challenge.Macaroon.Should().Be("abc123");
        challenge.Invoice.Should().Be("lnbc10u1ptest");
    }

    [Fact]
    public void Parse_LsatPrefix_BackwardsCompatible()
    {
        var header = "LSAT macaroon=\"abc123\", invoice=\"lnbc10u1ptest\"";
        var challenge = L402Challenge.Parse(header);
        challenge.Macaroon.Should().Be("abc123");
        challenge.Invoice.Should().Be("lnbc10u1ptest");
    }

    [Fact]
    public void Parse_CaseInsensitive()
    {
        var header = "l402 macaroon=\"abc123\", invoice=\"lnbc10u1ptest\"";
        var challenge = L402Challenge.Parse(header);
        challenge.Macaroon.Should().Be("abc123");
        challenge.Invoice.Should().Be("lnbc10u1ptest");
    }

    [Fact]
    public void Parse_EmptyHeader_Throws()
    {
        var act = () => L402Challenge.Parse("");
        act.Should().Throw<ChallengeParseException>()
            .Where(e => e.Reason == "empty header");
    }

    [Fact]
    public void Parse_NullHeader_Throws()
    {
        var act = () => L402Challenge.Parse(null!);
        act.Should().Throw<ChallengeParseException>();
    }

    [Fact]
    public void Parse_NoChallenge_Throws()
    {
        var act = () => L402Challenge.Parse("Bearer token123");
        act.Should().Throw<ChallengeParseException>()
            .Where(e => e.Reason == "no L402/LSAT challenge found");
    }

    [Fact]
    public void Parse_MixedSpacing_Succeeds()
    {
        var header = """L402   macaroon="abc123"  ,  invoice="lnbc10u1ptest"  """;
        var challenge = L402Challenge.Parse(header);
        challenge.Macaroon.Should().Be("abc123");
        challenge.Invoice.Should().Be("lnbc10u1ptest");
    }

    [Fact]
    public void TryParse_ValidResponse_ReturnsChallenge()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.WwwAuthenticate.ParseAdd("""L402 macaroon="mac123", invoice="lnbc10u1ptest"  """);

        var challenge = L402Challenge.TryParse(response);
        challenge.Should().NotBeNull();
        challenge!.Macaroon.Should().Be("mac123");
        challenge.Invoice.Should().Be("lnbc10u1ptest");
    }

    [Fact]
    public void TryParse_NoWwwAuthenticate_ReturnsNull()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        var challenge = L402Challenge.TryParse(response);
        challenge.Should().BeNull();
    }

    [Fact]
    public void TryParse_NonL402Header_ReturnsNull()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.WwwAuthenticate.ParseAdd("Bearer realm=\"test\"");

        var challenge = L402Challenge.TryParse(response);
        challenge.Should().BeNull();
    }

    [Fact]
    public void Parse_LongMacaroon_Succeeds()
    {
        var longMac = new string('a', 500);
        var header = $"""L402 macaroon="{longMac}", invoice="lnbc10u1ptest"  """;
        var challenge = L402Challenge.Parse(header);
        challenge.Macaroon.Should().Be(longMac);
    }

    [Fact]
    public void Parse_UnquotedNoComma_Succeeds()
    {
        var header = "L402 macaroon=abc123 invoice=lnbc10u1ptest";
        var challenge = L402Challenge.Parse(header);
        challenge.Macaroon.Should().Be("abc123");
        challenge.Invoice.Should().Be("lnbc10u1ptest");
    }
}
