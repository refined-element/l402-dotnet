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

    // ── Amounts too large to represent ──
    //
    // The sats total is an int, so anything above ~21.47 BTC cannot be represented.
    // That must surface as "amount unknown -> refuse", not as a raw OverflowException
    // thrown out of the caller's SendAsync, which would escape the
    // InvoiceAmountUnknownException taxonomy the client documents.

    [Fact]
    public void ExtractAmountSats_AboveIntMaxSats_ReturnsNull()
    {
        // lnbc22... = 22 BTC = 2,200,000,000 sats > int.MaxValue (2,147,483,647).
        Bolt11Invoice.ExtractAmountSats("lnbc221ptest").Should().BeNull();
    }

    [Fact]
    public void ExtractAmountSats_AboveIntMaxSats_ViaMultiplier_ReturnsNull()
    {
        // lnbc100000m... = 100000 * 0.001 BTC = 100 BTC = 10,000,000,000 sats.
        Bolt11Invoice.ExtractAmountSats("lnbc100000m1ptest").Should().BeNull();
    }

    [Fact]
    public void ExtractAmountSats_AmountTooLargeForDecimal_ReturnsNull()
    {
        // 40 digits overflows decimal.Parse itself (decimal maxes out near 7.9e28).
        Bolt11Invoice.ExtractAmountSats("lnbc" + new string('9', 40) + "1ptest").Should().BeNull();
    }

    [Fact]
    public void ExtractAmountSats_JustBelowIntMaxSats_StillParses()
    {
        // 21 BTC = 2,100,000,000 sats, still under int.MaxValue — must NOT be
        // refused. Guards the overflow fix against over-refusing valid amounts.
        Bolt11Invoice.ExtractAmountSats("lnbc211ptest").Should().Be(2_100_000_000);
    }

    [Fact]
    public void ClassifyMissingAmount_AboveIntMaxSats_ReportsOutOfRange()
    {
        // An amount IS encoded, so blaming "no amount encoded" would misdescribe it.
        Bolt11Invoice.ClassifyMissingAmount("lnbc221ptest")
            .Should().Be(MissingAmountReason.AmountOutOfRange);
    }
}
