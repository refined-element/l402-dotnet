using FluentAssertions;

namespace L402Requests.Tests;

public class Bolt11InvoiceTests
{
    [Fact]
    public void ExtractAmountSats_MilliBtc()
    {
        // lnbc1m... = 0.001 BTC = 100,000 sats
        var sats = Bolt11Invoice.ExtractAmountSats("lnbc1m1ptest");
        sats.Should().Be(100_000);
    }

    [Fact]
    public void ExtractAmountSats_MicroBtc()
    {
        // lnbc10u... = 0.00001 BTC = 1,000 sats
        var sats = Bolt11Invoice.ExtractAmountSats("lnbc10u1ptest");
        sats.Should().Be(1_000);
    }

    [Fact]
    public void ExtractAmountSats_NanoBtc()
    {
        // lnbc100n... = 0.0000001 BTC = 10 sats
        var sats = Bolt11Invoice.ExtractAmountSats("lnbc100n1ptest");
        sats.Should().Be(10);
    }

    [Fact]
    public void ExtractAmountSats_PicoBtc()
    {
        // lnbc10000p... = 0.00000001 BTC = 1 sat
        var sats = Bolt11Invoice.ExtractAmountSats("lnbc10000p1ptest");
        sats.Should().Be(1);
    }

    [Fact]
    public void ExtractAmountSats_NoMultiplier_BtcDirect()
    {
        // lnbc1... = 1 BTC = 100,000,000 sats
        var sats = Bolt11Invoice.ExtractAmountSats("lnbc11ptest");
        sats.Should().Be(100_000_000);
    }

    [Fact]
    public void ExtractAmountSats_Testnet()
    {
        var sats = Bolt11Invoice.ExtractAmountSats("lntb10u1ptest");
        sats.Should().Be(1_000);
    }

    [Fact]
    public void ExtractAmountSats_Regtest()
    {
        var sats = Bolt11Invoice.ExtractAmountSats("lnbcrt10u1ptest");
        sats.Should().Be(1_000);
    }

    [Fact]
    public void ExtractAmountSats_Signet()
    {
        var sats = Bolt11Invoice.ExtractAmountSats("lntbs10u1ptest");
        sats.Should().Be(1_000);
    }

    [Fact]
    public void ExtractAmountSats_AnyAmount_ReturnsNull()
    {
        // No amount specified
        var sats = Bolt11Invoice.ExtractAmountSats("lnbc1ptest");
        sats.Should().BeNull();
    }

    [Fact]
    public void ExtractAmountSats_EmptyString_ReturnsNull()
    {
        Bolt11Invoice.ExtractAmountSats("").Should().BeNull();
    }

    [Fact]
    public void ExtractAmountSats_NullString_ReturnsNull()
    {
        Bolt11Invoice.ExtractAmountSats(null!).Should().BeNull();
    }

    [Fact]
    public void ExtractAmountSats_Invalid_ReturnsNull()
    {
        Bolt11Invoice.ExtractAmountSats("notaninvoice").Should().BeNull();
    }

    [Fact]
    public void ExtractAmountSats_CaseInsensitive()
    {
        var sats = Bolt11Invoice.ExtractAmountSats("LNBC10U1ptest");
        sats.Should().Be(1_000);
    }

    [Fact]
    public void ExtractAmountSats_WhitespaceHandling()
    {
        var sats = Bolt11Invoice.ExtractAmountSats("  lnbc10u1ptest  ");
        sats.Should().Be(1_000);
    }

    [Fact]
    public void ExtractAmountSats_500Sats()
    {
        // 500 sats = 5000n BTC
        var sats = Bolt11Invoice.ExtractAmountSats("lnbc5000n1ptest");
        sats.Should().Be(500);
    }

    [Fact]
    public void ExtractAmountSats_1Sat_NanoMultiplier()
    {
        // 1 sat = 10n BTC
        var sats = Bolt11Invoice.ExtractAmountSats("lnbc10n1ptest");
        sats.Should().Be(1);
    }
}
