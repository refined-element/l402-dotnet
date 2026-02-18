using FluentAssertions;
using L402Requests.Wallets;

namespace L402Requests.Tests.Wallets;

public class NwcWalletTests
{
    private const string ValidConnectionString =
        "nostr+walletconnect://ab1c2d3e4f5a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2?relay=wss://relay.example.com&secret=deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567";

    [Fact]
    public void Constructor_ValidConnectionString_Parses()
    {
        var wallet = new NwcWallet(ValidConnectionString);
        wallet.Name.Should().Be("NWC");
        wallet.SupportsPreimage.Should().BeTrue();
    }

    [Fact]
    public void Constructor_MissingRelay_Throws()
    {
        var act = () => new NwcWallet("nostr+walletconnect://pubkey?secret=deadbeef");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*relay*");
    }

    [Fact]
    public void Constructor_MissingSecret_Throws()
    {
        var act = () => new NwcWallet("nostr+walletconnect://pubkey?relay=wss://relay.example.com");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*secret*");
    }

    [Fact]
    public void Properties_Correct()
    {
        var wallet = new NwcWallet(ValidConnectionString);
        wallet.Name.Should().Be("NWC");
        wallet.SupportsPreimage.Should().BeTrue();
    }
}
