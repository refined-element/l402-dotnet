using System.Net;
using FluentAssertions;

namespace L402Requests.Tests;

public class PaymentChallengeTests
{
    [Fact]
    public void TryParsePaymentChallenge_PrefersL402WhenBothPresent()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.WwwAuthenticate.ParseAdd("L402 macaroon=\"mac123\", invoice=\"lnbc10u1ptest\"");
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            "Payment realm=\"api.example.com\", method=\"lightning\", invoice=\"lnbc200n1pmpp\", amount=\"200\", currency=\"sat\"");

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().NotBeNull();
        challenge.Should().BeOfType<L402Challenge>();
        var l402 = (L402Challenge)challenge!;
        l402.Macaroon.Should().Be("mac123");
        l402.Invoice.Should().Be("lnbc10u1ptest");
    }

    [Fact]
    public void TryParsePaymentChallenge_FallsBackToMpp()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            "Payment realm=\"api.example.com\", method=\"lightning\", invoice=\"lnbc200n1pmpp\", amount=\"200\", currency=\"sat\"");

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().NotBeNull();
        challenge.Should().BeOfType<MppChallenge>();
        var mpp = (MppChallenge)challenge!;
        mpp.Invoice.Should().Be("lnbc200n1pmpp");
        mpp.Amount.Should().Be("200");
        mpp.Realm.Should().Be("api.example.com");
    }

    [Fact]
    public void TryParsePaymentChallenge_NoHeaders_ReturnsNull()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeNull();
    }

    [Fact]
    public void TryParsePaymentChallenge_NonPaymentHeaders_ReturnsNull()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.WwwAuthenticate.ParseAdd("Bearer realm=\"test\"");

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().BeNull();
    }

    [Fact]
    public void TryParsePaymentChallenge_OnlyL402_ReturnsL402()
    {
        var response = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
        response.Headers.WwwAuthenticate.ParseAdd("L402 macaroon=\"mac123\", invoice=\"lnbc10u1ptest\"");

        var challenge = L402Challenge.TryParsePaymentChallenge(response);

        challenge.Should().NotBeNull();
        challenge.Should().BeOfType<L402Challenge>();
    }

    [Fact]
    public void TryParsePaymentChallenge_L402ImplementsInterface()
    {
        var l402 = new L402Challenge("mac123", "lnbc10u1ptest");
        IPaymentChallenge paymentChallenge = l402;
        paymentChallenge.Invoice.Should().Be("lnbc10u1ptest");
    }
}
