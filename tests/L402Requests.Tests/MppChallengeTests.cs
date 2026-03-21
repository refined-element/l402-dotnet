using FluentAssertions;

namespace L402Requests.Tests;

public class MppChallengeTests
{
    [Fact]
    public void Parse_ValidPaymentHeader_ReturnsMppChallenge()
    {
        var header = "Payment realm=\"api.example.com\", method=\"lightning\", invoice=\"lnbc100n1pjtest\", amount=\"100\", currency=\"sat\"";
        var result = MppChallenge.Parse(header);
        result.Should().NotBeNull();
        result!.Invoice.Should().Be("lnbc100n1pjtest");
        result.Amount.Should().Be("100");
        result.Realm.Should().Be("api.example.com");
    }

    [Fact]
    public void Parse_NonLightningMethod_ReturnsNull()
    {
        var header = "Payment realm=\"test\", method=\"stripe\", invoice=\"lnbc100n1pjtest\"";
        var result = MppChallenge.Parse(header);
        result.Should().BeNull();
    }

    [Fact]
    public void Parse_MissingInvoice_ReturnsNull()
    {
        var result = MppChallenge.Parse("Payment method=\"lightning\", amount=\"100\"");
        result.Should().BeNull();
    }

    [Fact]
    public void Parse_NullOrEmpty_ReturnsNull()
    {
        MppChallenge.Parse(null).Should().BeNull();
        MppChallenge.Parse("").Should().BeNull();
        MppChallenge.Parse("  ").Should().BeNull();
    }

    [Fact]
    public void Parse_MinimalHeader_Works()
    {
        var result = MppChallenge.Parse("Payment method=\"lightning\", invoice=\"lnbc100n1pjtest\"");
        result.Should().NotBeNull();
        result!.Invoice.Should().Be("lnbc100n1pjtest");
        result.Amount.Should().BeNull();
        result.Realm.Should().BeNull();
    }

    [Fact]
    public void Parse_CaseInsensitiveMethod_Works()
    {
        var result = MppChallenge.Parse("Payment method=\"Lightning\", invoice=\"lnbc100n1pjtest\"");
        result.Should().NotBeNull();
        result!.Invoice.Should().Be("lnbc100n1pjtest");
    }

    [Fact]
    public void Parse_L402Header_ReturnsNull()
    {
        var result = MppChallenge.Parse("L402 macaroon=\"abc123\", invoice=\"lnbc10u1ptest\"");
        result.Should().BeNull();
    }

    [Fact]
    public void MppChallenge_ImplementsIPaymentChallenge()
    {
        var challenge = new MppChallenge { Invoice = "lnbc100n1pjtest" };
        IPaymentChallenge paymentChallenge = challenge;
        paymentChallenge.Invoice.Should().Be("lnbc100n1pjtest");
    }

    [Fact]
    public void Parse_InvoiceBeforeMethod_Works()
    {
        // Parameters in reverse order: invoice before method
        var header = "Payment invoice=\"lnbc100n1pjtest\", method=\"lightning\"";
        var result = MppChallenge.Parse(header);
        result.Should().NotBeNull();
        result!.Invoice.Should().Be("lnbc100n1pjtest");
    }

    [Fact]
    public void Parse_AnyParameterOrder_Works()
    {
        // amount, invoice, realm, method — all out of typical order
        var header = "Payment amount=\"500\", invoice=\"lnbc500n1pjtest\", realm=\"api.test.com\", method=\"lightning\"";
        var result = MppChallenge.Parse(header);
        result.Should().NotBeNull();
        result!.Invoice.Should().Be("lnbc500n1pjtest");
        result.Amount.Should().Be("500");
        result.Realm.Should().Be("api.test.com");
    }

    [Fact]
    public void Parse_UnquotedValues_Works()
    {
        var header = "Payment method=lightning, invoice=lnbc100n1pjtest";
        var result = MppChallenge.Parse(header);
        result.Should().NotBeNull();
        result!.Invoice.Should().Be("lnbc100n1pjtest");
    }

    [Fact]
    public void Parse_NotAnchoredToPaymentScheme_ReturnsNull()
    {
        // Header does not start with "Payment" — should not match
        var header = "Bearer realm=\"test\", Payment method=\"lightning\", invoice=\"lnbc100n1pjtest\"";
        var result = MppChallenge.Parse(header);
        result.Should().BeNull();
    }
}
