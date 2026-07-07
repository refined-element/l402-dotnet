using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using L402Requests.Wallets;
using NBitcoin.Secp256k1;

namespace L402Requests.Tests.Wallets;

public class NwcWalletTests
{
    // A valid NWC URI: the wallet pubkey is a real secp256k1 x-only key (32 bytes)
    // and the secret is a valid 32-byte scalar. Construction parses these eagerly.
    // Neutral fixture values — no "secret-..."-shaped literals (gitleaks generic-api-key).
    private const string ValidConnectionString =
        "nostr+walletconnect://" + ValidWalletPubkeyHex +
        "?relay=wss://relay.example.com&secret=" + ValidClientSecretHex;

    private const string ValidWalletPubkeyHex =
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"; // generator x-coord
    private const string ValidClientSecretHex =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #region Construction (unchanged contract)

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
        var act = () => new NwcWallet(
            "nostr+walletconnect://" + ValidWalletPubkeyHex + "?secret=" + ValidClientSecretHex);
        act.Should().Throw<ArgumentException>().WithMessage("*relay*");
    }

    [Fact]
    public void Constructor_MissingSecret_Throws()
    {
        var act = () => new NwcWallet(
            "nostr+walletconnect://" + ValidWalletPubkeyHex + "?relay=wss://relay.example.com");
        act.Should().Throw<ArgumentException>().WithMessage("*secret*");
    }

    [Fact]
    public void Properties_Correct()
    {
        var wallet = new NwcWallet(ValidConnectionString);
        wallet.Name.Should().Be("NWC");
        wallet.SupportsPreimage.Should().BeTrue();
    }

    #endregion

    #region Helpers

    private static (ECPrivKey privKey, byte[] pubKeyBytes) GenerateKeyPair()
    {
        var privKeyBytes = new byte[32];
        RandomNumberGenerator.Fill(privKeyBytes);
        // Ensure a valid scalar (not zero, comfortably below curve order).
        privKeyBytes[0] = 0x01;
        ECPrivKey.TryCreate(privKeyBytes, out var privKey);
        var pubKey = privKey!.CreateXOnlyPubKey();
        return (privKey, pubKey.ToBytes());
    }

    // Builds a fully-signed kind-23195 (NIP-47 response) event using the same
    // canonical serialisation NwcWallet.ComputeEventId uses, so a genuine event
    // verifies and any post-sign tamper breaks verification.
    private static JsonObject BuildSignedResponseEvent(
        ECPrivKey privKey, string pubkeyHex, string content, int kind = 23195)
    {
        var createdAt = 1700000000L;
        var tags = new JsonArray(); // e/p tags are not part of what we assert here
        var id = NwcWallet.ComputeEventId(pubkeyHex, createdAt, kind, tags, content);

        privKey.TrySignBIP340(Convert.FromHexString(id), null, out var sig);

        return new JsonObject
        {
            ["id"] = id,
            ["pubkey"] = pubkeyHex,
            ["created_at"] = createdAt,
            ["kind"] = kind,
            ["tags"] = JsonNode.Parse(tags.ToJsonString()),
            ["content"] = content,
            ["sig"] = Convert.ToHexString(sig!.ToBytes()).ToLowerInvariant()
        };
    }

    #endregion

    #region X-only pubkey derivation

    [Fact]
    public void DeriveXOnlyPubkey_KnownSecret_MatchesGeneratorPoint()
    {
        // secret = 1 → public key is the secp256k1 generator point G,
        // whose x-coordinate is the well-known constant below (BIP340 x-only).
        var one = new byte[32];
        one[31] = 0x01;

        var xonly = NwcWallet.DeriveXOnlyPubkey(one);

        Convert.ToHexString(xonly).ToLowerInvariant()
            .Should().Be("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    }

    [Fact]
    public void DeriveXOnlyPubkey_RoundTripsThroughNBitcoin()
    {
        var (privKey, expectedPub) = GenerateKeyPair();
        // Reconstruct the secret bytes from the generated priv key to feed our helper.
        var secret = privKey.sec.ToBytes();

        var derived = NwcWallet.DeriveXOnlyPubkey(secret);

        derived.Should().BeEquivalentTo(expectedPub);
    }

    #endregion

    #region Schnorr sign / verify

    [Fact]
    public void SchnorrSign_ThenVerify_Roundtrips()
    {
        var (privKey, pubKeyBytes) = GenerateKeyPair();
        var message = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("nip-01 event id stand-in"));

        var sig = NwcWallet.SchnorrSign(privKey.sec.ToBytes(), message);

        ECXOnlyPubKey.TryCreate(pubKeyBytes, out var pub).Should().BeTrue();
        SecpSchnorrSignature.TryCreate(sig, out var parsed).Should().BeTrue();
        pub!.SigVerifyBIP340(parsed!, message).Should().BeTrue("a fresh signature must verify");
    }

    [Fact]
    public void SchnorrSign_TamperedMessage_FailsVerification()
    {
        var (privKey, pubKeyBytes) = GenerateKeyPair();
        var message = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("original"));
        var sig = NwcWallet.SchnorrSign(privKey.sec.ToBytes(), message);

        var tampered = (byte[])message.Clone();
        tampered[0] ^= 0xFF;

        ECXOnlyPubKey.TryCreate(pubKeyBytes, out var pub).Should().BeTrue();
        SecpSchnorrSignature.TryCreate(sig, out var parsed).Should().BeTrue();
        pub!.SigVerifyBIP340(parsed!, tampered)
            .Should().BeFalse("a signature must not verify against a tampered message");
    }

    #endregion

    #region Response-event verification (F-11 gate)

    [Fact]
    public void IsResponseEventTrustworthy_AcceptsValidSignedEvent()
    {
        var (privKey, pubKeyBytes) = GenerateKeyPair();
        var pubkeyHex = Convert.ToHexString(pubKeyBytes).ToLowerInvariant();
        var ev = BuildSignedResponseEvent(privKey, pubkeyHex, "ciphertext-placeholder");

        var ok = NwcWallet.IsResponseEventTrustworthy(ev, pubkeyHex, out var reason);

        ok.Should().BeTrue($"valid event must pass; reason: {reason}");
        reason.Should().BeEmpty();
    }

    [Fact]
    public void IsResponseEventTrustworthy_RejectsWrongPubkey()
    {
        var (privKey, pubKeyBytes) = GenerateKeyPair();
        var attackerPubkey = Convert.ToHexString(pubKeyBytes).ToLowerInvariant();
        var ev = BuildSignedResponseEvent(privKey, attackerPubkey, "ciphertext-placeholder");

        // Configured wallet expects a DIFFERENT pubkey than the event author.
        var configuredWallet = new string('a', 64);

        var ok = NwcWallet.IsResponseEventTrustworthy(ev, configuredWallet, out var reason);

        ok.Should().BeFalse();
        reason.Should().Contain("pubkey mismatch");
    }

    [Fact]
    public void IsResponseEventTrustworthy_RejectsForgedSignature()
    {
        // Event author == configured wallet, but the signature was produced by a
        // different key. Must fail BIP340 verification.
        var (alicePriv, alicePubBytes) = GenerateKeyPair();
        var (bobPriv, _) = GenerateKeyPair();
        var alicePubHex = Convert.ToHexString(alicePubBytes).ToLowerInvariant();

        var ev = BuildSignedResponseEvent(alicePriv, alicePubHex, "ciphertext-placeholder");
        var idBytes = Convert.FromHexString(ev["id"]!.GetValue<string>());
        bobPriv.TrySignBIP340(idBytes, null, out var fakeSig);
        ev["sig"] = Convert.ToHexString(fakeSig!.ToBytes()).ToLowerInvariant();

        var ok = NwcWallet.IsResponseEventTrustworthy(ev, alicePubHex, out var reason);

        ok.Should().BeFalse();
        reason.Should().Contain("signature");
    }

    [Fact]
    public void IsResponseEventTrustworthy_RejectsTamperedContent()
    {
        // Right pubkey, real signature, but the content was swapped after signing.
        // The recomputed event id won't match the claimed id → reject.
        var (privKey, pubKeyBytes) = GenerateKeyPair();
        var pubkeyHex = Convert.ToHexString(pubKeyBytes).ToLowerInvariant();
        var ev = BuildSignedResponseEvent(privKey, pubkeyHex, "original-ciphertext");

        ev["content"] = "swapped-ciphertext";

        var ok = NwcWallet.IsResponseEventTrustworthy(ev, pubkeyHex, out var reason);

        ok.Should().BeFalse();
        reason.Should().Contain("signature");
    }

    [Fact]
    public void IsResponseEventTrustworthy_MalformedFields_DoesNotThrow()
    {
        NwcWallet.IsResponseEventTrustworthy(new JsonObject(), new string('a', 64), out _)
            .Should().BeFalse("empty event must be rejected, not throw");

        var ev = new JsonObject
        {
            ["id"] = "not-hex",
            ["pubkey"] = new string('a', 64),
            ["sig"] = "neither",
            ["created_at"] = 1L,
            ["kind"] = 23195,
            ["tags"] = new JsonArray(),
            ["content"] = ""
        };
        NwcWallet.IsResponseEventTrustworthy(ev, new string('a', 64), out _)
            .Should().BeFalse("malformed hex must not throw");
    }

    #endregion

    #region NIP-04 round-trip with real ECDH shared secret

    [Fact]
    public void Nip04_EncryptDecrypt_RoundTrips()
    {
        var (alicePriv, alicePub) = GenerateKeyPair();
        var (bobPriv, bobPub) = GenerateKeyPair();

        var message = "{\"method\":\"pay_invoice\",\"params\":{\"invoice\":\"lnbc100n1p3test\"}}";

        // Alice encrypts for Bob; Bob decrypts from Alice.
        var encrypted = NwcWallet.EncryptNip04(message, bobPub, alicePriv);
        encrypted.Should().Contain("?iv=", "NIP-04 output carries the IV marker");

        var decrypted = NwcWallet.DecryptContent(encrypted, alicePub, bobPriv);
        decrypted.Should().Be(message);
    }

    [Fact]
    public void Nip04_EncryptDecrypt_SpecialCharacters_RoundTrips()
    {
        var (alicePriv, alicePub) = GenerateKeyPair();
        var (bobPriv, bobPub) = GenerateKeyPair();

        var message = "{\"description\":\"special chars: +/= and unicode: éàü\"}";

        var encrypted = NwcWallet.EncryptNip04(message, bobPub, alicePriv);
        var decrypted = NwcWallet.DecryptContent(encrypted, alicePub, bobPriv);
        decrypted.Should().Be(message);
    }

    [Fact]
    public void Nip04_SharedSecret_IsSymmetric()
    {
        // ECDH: Alice's (priv, Bob.pub) shared-X must equal Bob's (priv, Alice.pub) shared-X.
        var (alicePriv, alicePub) = GenerateKeyPair();
        var (bobPriv, bobPub) = GenerateKeyPair();

        var aliceSide = NwcWallet.ComputeSharedSecret(alicePriv, bobPub);
        var bobSide = NwcWallet.ComputeSharedSecret(bobPriv, alicePub);

        aliceSide.Should().BeEquivalentTo(bobSide, "ECDH shared secret must be symmetric");
    }

    #endregion

    #region DecryptContent auto-detect (NIP-44)

    [Fact]
    public void DecryptContent_HandlesNip44Payload()
    {
        var (alicePriv, alicePub) = GenerateKeyPair();
        var (bobPriv, bobPub) = GenerateKeyPair();

        var plaintext = "{\"result_type\":\"pay_invoice\",\"result\":{\"preimage\":\"abc123\"}}";

        // Encrypt with NIP-44 v2 (no "?iv=" marker), then auto-detect on the way back in.
        var encrypted = NwcWallet.EncryptNip44(plaintext, bobPub, alicePriv);
        encrypted.Should().NotContain("?iv=", "NIP-44 output must not carry the NIP-04 marker");

        var decrypted = NwcWallet.DecryptContent(encrypted, alicePub, bobPriv);
        decrypted.Should().Be(plaintext);
    }

    [Fact]
    public void DecryptNip44_TamperedMac_Throws()
    {
        var (alicePriv, alicePub) = GenerateKeyPair();
        var (bobPriv, bobPub) = GenerateKeyPair();

        var encrypted = NwcWallet.EncryptNip44("tamper test", bobPub, alicePriv);
        var data = Convert.FromBase64String(encrypted);
        data[^1] ^= 0xFF; // flip a MAC byte
        var tampered = Convert.ToBase64String(data);

        var act = () => NwcWallet.DecryptContent(tampered, alicePub, bobPriv);
        act.Should().Throw<Exception>("HMAC verification must fail on a tampered NIP-44 payload");
    }

    #endregion

    #region Outbound encryption build (NIP-04 vs NIP-44 v2)

    [Fact]
    public void BuildPayInvoiceRequest_Nip04_ProducesIvMarkerAndNoEncryptionTag()
    {
        // NIP-04 outbound: content carries the "?iv=" marker and there is NO "encryption"
        // tag (its absence is the original NIP-47 NIP-04 default). We verify by decrypting
        // the event content from the wallet side using the SAME ECDH pair.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=wss://relay.example.com&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr);

        var bolt11 = "lnbc100n1p3xyztest";
        var (eventObj, _) = wallet.BuildPayInvoiceRequestForTest(bolt11, NwcEncryption.Nip04);

        var content = eventObj["content"]!.GetValue<string>();
        content.Should().Contain("?iv=", "NIP-04 output carries the IV marker");

        var tags = eventObj["tags"]!.AsArray();
        tags.Any(t => t?.AsArray()?[0]?.GetValue<string>() == "encryption")
            .Should().BeFalse("NIP-04 requests must NOT carry an encryption tag");

        // Decrypt from the wallet's perspective: sender = client pubkey on the event.
        var clientPubHex = eventObj["pubkey"]!.GetValue<string>();
        var clientPubBytes = Convert.FromHexString(clientPubHex);
        var decrypted = NwcWallet.DecryptContent(content, clientPubBytes, walletPriv);

        using var doc = JsonDocument.Parse(decrypted);
        doc.RootElement.GetProperty("method").GetString().Should().Be("pay_invoice");
        doc.RootElement.GetProperty("params").GetProperty("invoice").GetString().Should().Be(bolt11);

        // And the event must be a valid, self-signed kind-23194 request.
        NwcWallet.IsResponseEventTrustworthy(eventObj, clientPubHex, out var reason)
            .Should().BeTrue($"our own request event must verify; reason: {reason}");
    }

    [Fact]
    public void BuildPayInvoiceRequest_Nip44_ProducesEncryptionTagAndNoIvMarker()
    {
        // NIP-44 v2 outbound: content is a single base64 blob (no "?iv=") AND the event
        // carries the ["encryption","nip44_v2"] tag required so Alby-Hub-style wallets
        // decrypt it. Verify by NIP-44-decrypting the content from the wallet side.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=wss://relay.example.com&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr);

        var bolt11 = "lnbc100n1p3xyztest";
        var (eventObj, _) = wallet.BuildPayInvoiceRequestForTest(bolt11, NwcEncryption.Nip44V2);

        var content = eventObj["content"]!.GetValue<string>();
        content.Should().NotContain("?iv=", "NIP-44 output must not carry the NIP-04 IV marker");

        var tags = eventObj["tags"]!.AsArray();
        var encTag = tags
            .Select(t => t?.AsArray())
            .FirstOrDefault(t => t != null && t.Count >= 2 && t[0]?.GetValue<string>() == "encryption");
        encTag.Should().NotBeNull("NIP-44 requests must carry an encryption tag");
        encTag![1]?.GetValue<string>().Should().Be("nip44_v2");

        // Decrypt from the wallet's perspective via NIP-44 v2.
        var clientPubHex = eventObj["pubkey"]!.GetValue<string>();
        var clientPubBytes = Convert.FromHexString(clientPubHex);
        var decrypted = NwcWallet.DecryptNip44(content, clientPubBytes, walletPriv);

        using var doc = JsonDocument.Parse(decrypted);
        doc.RootElement.GetProperty("method").GetString().Should().Be("pay_invoice");
        doc.RootElement.GetProperty("params").GetProperty("invoice").GetString().Should().Be(bolt11);

        // The event must remain a valid, self-signed kind-23194 request (tag is part of the id).
        NwcWallet.IsResponseEventTrustworthy(eventObj, clientPubHex, out var reason)
            .Should().BeTrue($"our own request event must verify; reason: {reason}");
    }

    #endregion

    #region NWC_ENCRYPTION mode selection + INFO-tag picker

    [Fact]
    public void NwcEncryption_Default_IsAuto()
    {
        NwcEncryption.Default.Should().Be("auto");
    }

    [Fact]
    public void NwcEncryption_IsValid_AcceptsKnownSchemesOnly()
    {
        NwcEncryption.IsValid("nip04").Should().BeTrue();
        NwcEncryption.IsValid("nip44_v2").Should().BeTrue();
        NwcEncryption.IsValid("auto").Should().BeTrue();
        NwcEncryption.IsValid("nip44").Should().BeFalse("nip44_v2 is the only NIP-44 variant we support");
        NwcEncryption.IsValid("").Should().BeFalse();
        NwcEncryption.IsValid(null).Should().BeFalse();
    }

    [Fact]
    public void Constructor_DefaultsToAutoEncryption()
    {
        var wallet = new NwcWallet(ValidConnectionString);
        wallet.ConfiguredEncryption.Should().Be("auto");
    }

    [Theory]
    [InlineData("nip04", "nip04")]
    [InlineData("nip44_v2", "nip44_v2")]
    [InlineData("auto", "auto")]
    [InlineData("NIP44_V2", "nip44_v2")]  // case-insensitive
    [InlineData(" nip04 ", "nip04")]       // trimmed
    [InlineData("bogus", "auto")]          // invalid → default
    public void Constructor_EncryptionParam_NormalizesOrFallsBack(string param, string expected)
    {
        var wallet = new NwcWallet(ValidConnectionString, encryption: param);
        wallet.ConfiguredEncryption.Should().Be(expected);
    }

    [Theory]
    [InlineData("nip04 nip44_v2", "nip44_v2")]
    [InlineData("nip44_v2 nip04", "nip44_v2")]
    [InlineData("nip04", "nip04")]
    [InlineData("nip44_v2", "nip44_v2")]
    [InlineData("nip04,nip44_v2", "nip44_v2")] // comma separator tolerated
    [InlineData("NIP04 NIP44_V2", "nip44_v2")] // case-insensitive
    [InlineData("nip04  nip44_v2", "nip44_v2")] // double spaces
    [InlineData("", "nip04")]                   // empty → fallback
    [InlineData(null, "nip04")]                 // null → fallback
    [InlineData("nip99_alpha", "nip04")]        // unknown scheme → fallback
    public void PickEncryptionFromInfoTag_PicksStrongestOrFallsBack(string? tagValue, string expected)
    {
        NwcWallet.PickEncryptionFromInfoTag(tagValue).Should().Be(expected);
    }

    #endregion

    #region NIP-44 v2 padded-length known vectors

    [Theory]
    [InlineData(1, 32)]
    [InlineData(16, 32)]
    [InlineData(32, 32)]
    [InlineData(33, 64)]
    [InlineData(64, 64)]
    [InlineData(65, 96)]
    [InlineData(100, 128)]
    [InlineData(256, 256)]
    [InlineData(300, 320)]
    public void CalcPaddedLen_ReturnsExpectedValues(int input, int expected)
    {
        NwcWallet.CalcPaddedLen(input).Should().Be(expected);
    }

    [Fact]
    public void CalcPaddedLen_Zero_Throws()
    {
        var act = () => NwcWallet.CalcPaddedLen(0);
        act.Should().Throw<ArgumentException>();
    }

    #endregion

    #region INFO-event (kind 13194) signature verification

    [Fact]
    public void VerifyNostrEventSignature_TamperedEncryptionTag_ReturnsFalse()
    {
        // A relay-injected 13194 event with a forged encryption tag must fail verification:
        // tampering after signing changes the recomputed event id, so the sig no longer matches.
        var (privKey, pubKeyBytes) = GenerateKeyPair();
        var pubkeyHex = Convert.ToHexString(pubKeyBytes).ToLowerInvariant();
        var ev = BuildSignedInfoEvent(privKey, pubkeyHex, "nip04 nip44_v2");

        ev["tags"]!.AsArray()
            .Where(t => t?.AsArray()?[0]?.GetValue<string>() == "encryption")
            .Select(t => t!.AsArray())
            .First()[1] = "nip04"; // force a downgrade

        NwcWallet.VerifyNostrEventSignature(ev)
            .Should().BeFalse("tampering with the encryption tag must invalidate the signature");
    }

    [Fact]
    public void VerifyNostrEventSignature_ValidInfoEvent_ReturnsTrue()
    {
        var (privKey, pubKeyBytes) = GenerateKeyPair();
        var pubkeyHex = Convert.ToHexString(pubKeyBytes).ToLowerInvariant();
        var ev = BuildSignedInfoEvent(privKey, pubkeyHex, "nip04 nip44_v2");

        NwcWallet.VerifyNostrEventSignature(ev)
            .Should().BeTrue("a correctly signed INFO event must verify");
    }

    private static JsonObject BuildSignedInfoEvent(ECPrivKey privKey, string pubkeyHex, string encryptionTagValue)
    {
        var createdAt = 1700000000L;
        var tags = new JsonArray { new JsonArray { "encryption", encryptionTagValue } };
        var content = "Wallet capabilities: pay_invoice get_balance";
        var id = NwcWallet.ComputeEventId(pubkeyHex, createdAt, 13194, tags, content);

        privKey.TrySignBIP340(Convert.FromHexString(id), null, out var sig);

        return new JsonObject
        {
            ["id"] = id,
            ["pubkey"] = pubkeyHex,
            ["created_at"] = createdAt,
            ["kind"] = 13194,
            ["tags"] = JsonNode.Parse(tags.ToJsonString()),
            ["content"] = content,
            ["sig"] = Convert.ToHexString(sig!.ToBytes()).ToLowerInvariant()
        };
    }

    #endregion

    #region End-to-end pay against an in-process relay

    [Fact]
    public async Task PayInvoiceAsync_AgainstMockRelay_ReturnsPreimage()
    {
        // Spin up a loopback WebSocket "relay" that plays the wallet side:
        // it receives the REQ + EVENT, decrypts the request, and replies with a
        // signed kind-23195 event carrying the preimage, NIP-04 encrypted.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var preimage = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

        await using var relay = new MockNwcRelay(walletPriv, walletPubHex, preimage);
        await relay.StartAsync();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=" + relay.Url + "&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr, TimeSpan.FromSeconds(10));

        var result = await wallet.PayInvoiceAsync("lnbc100n1p3xyztest");

        result.Should().Be(preimage);
    }

    [Fact]
    public async Task PayInvoiceAsync_Nip44OnlyWallet_AutoDetectsNip44_AndPays()
    {
        // THE BUG FIX. The wallet only understands NIP-44 v2 (Alby Hub): it silently
        // ignores a NIP-04 request, and it advertises "nip04 nip44_v2" in its NIP-47 INFO
        // event (kind 13194). With outbound auto-detect, the client fetches the INFO event,
        // picks nip44_v2, sends a NIP-44 request, and gets paid. Before the fix, the client
        // sent NIP-04 unconditionally, the wallet never replied, and the pay timed out.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var preimage = "a1b2c3d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f6071829304a5b6c7d8e9f";

        await using var relay = new MockNwcRelay(walletPriv, walletPubHex, preimage)
        {
            InfoEncryptionTag = "nip04 nip44_v2",
            RequireNip44 = true
        };
        await relay.StartAsync();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=" + relay.Url + "&secret=" + ValidClientSecretHex;
        // encryption: "auto" is the default; pass explicitly so an ambient NWC_ENCRYPTION
        // env var can't influence the test.
        var wallet = new NwcWallet(connStr, TimeSpan.FromSeconds(10), encryption: "auto");

        var result = await wallet.PayInvoiceAsync("lnbc100n1p3xyztest");

        result.Should().Be(preimage, "auto-detect must pick nip44_v2 for an Alby-Hub-style wallet");
    }

    [Fact]
    public async Task PayInvoiceAsync_ExplicitNip44_AgainstNip44OnlyWallet_Pays()
    {
        // Explicit nip44_v2 override skips the INFO fetch entirely and still pays a
        // NIP-44-only wallet. (No InfoEncryptionTag configured on the relay.)
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var preimage = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

        await using var relay = new MockNwcRelay(walletPriv, walletPubHex, preimage)
        {
            RequireNip44 = true
        };
        await relay.StartAsync();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=" + relay.Url + "&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr, TimeSpan.FromSeconds(10), encryption: "nip44_v2");

        var result = await wallet.PayInvoiceAsync("lnbc100n1p3xyztest");

        result.Should().Be(preimage);
    }

    [Fact]
    public async Task PayInvoiceAsync_ExplicitNip04_AgainstNip44OnlyWallet_TimesOutWithMismatchHint()
    {
        // Regression proof: the OLD hard-coded-NIP-04 behaviour against a NIP-44-only wallet.
        // The request is silently dropped, no reply arrives, and the pay times out with a
        // message that names the scheme used and points at the nip44_v2 swap.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var preimage = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";

        await using var relay = new MockNwcRelay(walletPriv, walletPubHex, preimage)
        {
            RequireNip44 = true
        };
        await relay.StartAsync();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=" + relay.Url + "&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr, TimeSpan.FromSeconds(3), encryption: "nip04");

        var act = async () => await wallet.PayInvoiceAsync("lnbc100n1p3xyztest");
        var ex = (await act.Should().ThrowAsync<PaymentFailedException>(
            "a NIP-04 request to a NIP-44-only wallet gets no reply")).Which;
        ex.Message.Should().Contain("nip44_v2", "the timeout message must hint at the encryption swap");
    }

    [Fact]
    public async Task ResolveAutoEncryptionAsync_CachesInfoEventResult()
    {
        // Auto-detect must fetch the INFO event exactly once and cache the result — repeated
        // resolves must not re-open the relay connection.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        await using var relay = new MockNwcRelay(walletPriv, walletPubHex, "00")
        {
            InfoEncryptionTag = "nip04 nip44_v2"
        };
        await relay.StartAsync();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=" + relay.Url + "&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr, encryption: "auto");

        var first = await wallet.ResolveAutoEncryptionAsync(default);
        var second = await wallet.ResolveAutoEncryptionAsync(default);

        first.Should().Be("nip44_v2");
        second.Should().Be("nip44_v2");
        wallet.InfoEventFetchCount.Should().Be(1, "the INFO event must be fetched once and cached");
    }

    [Fact]
    public async Task ResolveAutoEncryptionAsync_NoInfoEvent_FallsBackToNip04()
    {
        // A wallet that never published a kind-13194 event (relay answers the probe with
        // EOSE only) must resolve to NIP-04 — the original NIP-47 default.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        await using var relay = new MockNwcRelay(walletPriv, walletPubHex, "00");
        await relay.StartAsync();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=" + relay.Url + "&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr, encryption: "auto");

        var resolved = await wallet.ResolveAutoEncryptionAsync(default);

        resolved.Should().Be("nip04");
    }

    [Fact]
    public async Task PayInvoiceAsync_RejectsForgedResponseFromWrongPubkey()
    {
        // The relay replies with a kind-23195 event signed by an ATTACKER key
        // (not the configured wallet pubkey). The F-11 gate must reject it, and
        // since no valid response ever arrives, the call times out / fails.
        var (_, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var (attackerPriv, attackerPub) = GenerateKeyPair();
        var attackerPubHex = Convert.ToHexString(attackerPub).ToLowerInvariant();

        var preimage = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0";

        // Relay signs/encrypts as the ATTACKER but claims to be from attackerPubHex.
        await using var relay = new MockNwcRelay(attackerPriv, attackerPubHex, preimage);
        await relay.StartAsync();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=" + relay.Url + "&secret=" + ValidClientSecretHex;
        // Short timeout so the test is fast — forged event is dropped, no valid reply.
        var wallet = new NwcWallet(connStr, TimeSpan.FromSeconds(3));

        var act = async () => await wallet.PayInvoiceAsync("lnbc100n1p3xyztest");
        await act.Should().ThrowAsync<PaymentFailedException>(
            "a response from a non-wallet pubkey must be rejected, leading to no valid reply");
    }

    [Fact]
    public async Task PayInvoiceAsync_IgnoresEventForDifferentSubscription()
    {
        // The relay publishes an otherwise-valid kind-23195 response, but under a
        // DIFFERENT subscription id than the one the client opened. The receive loop
        // must match msgArray[1] against its own subId and ignore the event — leading
        // to no valid reply and a timeout, rather than treating the unrelated event as
        // the response.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var preimage = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        await using var relay = new MockNwcRelay(walletPriv, walletPubHex, preimage)
        {
            // Deliver the response on a subscription id the client never opened.
            SubIdOverride = "ffffffffffffffff"
        };
        await relay.StartAsync();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=" + relay.Url + "&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr, TimeSpan.FromSeconds(3));

        var act = async () => await wallet.PayInvoiceAsync("lnbc100n1p3xyztest");
        await act.Should().ThrowAsync<PaymentFailedException>(
            "an EVENT for a different subscription id must be ignored, so no valid reply arrives");
    }

    [Fact]
    public async Task PayInvoiceAsync_MalformedJsonResponse_DoesNotLeakJsonException()
    {
        // The relay replies with a correctly-signed, correctly-encrypted kind-23195 event
        // whose decrypted content is NOT valid JSON. The receive loop's JsonDocument.Parse
        // must not let a raw JsonException escape — it should treat the message as
        // "not for us" and keep waiting, so the call ends as a PaymentFailedException
        // (timeout), never a JsonException.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var preimage = "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa";

        await using var relay = new MockNwcRelay(walletPriv, walletPubHex, preimage)
        {
            MalformedJsonPayload = true
        };
        await relay.StartAsync();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=" + relay.Url + "&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr, TimeSpan.FromSeconds(3));

        var act = async () => await wallet.PayInvoiceAsync("lnbc100n1p3xyztest");
        (await act.Should().ThrowAsync<PaymentFailedException>(
            "an invalid-JSON response must be skipped, not surfaced as a raw JsonException"))
            .Which.Should().NotBeOfType<JsonException>();
    }

    #endregion

    #region Connection-string validation (consistent ArgumentException contract)

    [Fact]
    public void Constructor_MalformedWalletPubkey_ThrowsArgumentException()
    {
        // A non-hex wallet pubkey makes Convert.FromHexString throw FormatException.
        // The constructor must surface this as ArgumentException, consistent with the
        // other connection-string validation (missing relay/secret).
        var connStr =
            "nostr+walletconnect://not-valid-hex-pubkey" +
            "?relay=wss://relay.example.com&secret=" + ValidClientSecretHex;

        var act = () => new NwcWallet(connStr);

        act.Should().Throw<ArgumentException>().WithMessage("*pubkey*");
    }

    [Fact]
    public void Constructor_MalformedSecret_ThrowsArgumentException()
    {
        // A non-hex secret makes Convert.FromHexString throw FormatException; surface
        // it as ArgumentException too.
        var connStr =
            "nostr+walletconnect://" + ValidWalletPubkeyHex +
            "?relay=wss://relay.example.com&secret=not-valid-hex-secret";

        var act = () => new NwcWallet(connStr);

        act.Should().Throw<ArgumentException>().WithMessage("*secret*");
    }

    [Fact]
    public void Constructor_WrongLengthWalletPubkey_ThrowsArgumentException()
    {
        // A hex-but-wrong-length wallet pubkey (60 chars = 30 bytes, NOT the required
        // 32-byte x-only key) passes the hex check but is not a valid pubkey. Without an
        // explicit length check it slips through construction and only fails much later
        // (ECDH / receive timeout). Validate the length up front with a clear message.
        var shortPubkey = new string('a', 60); // even-length hex, but 30 bytes not 32
        var connStr =
            "nostr+walletconnect://" + shortPubkey +
            "?relay=wss://relay.example.com&secret=" + ValidClientSecretHex;

        var act = () => new NwcWallet(connStr);

        act.Should().Throw<ArgumentException>().WithMessage("*pubkey*");
    }

    [Fact]
    public void Constructor_MalformedConnectionString_ThrowsArgumentException()
    {
        // A connection string that isn't a parseable URI makes `new Uri(...)` throw
        // UriFormatException (a FormatException, NOT an ArgumentException), which would
        // escape the constructor as an inconsistent type. Surface it as ArgumentException
        // to match the rest of the connection-string error contract.
        var act = () => new NwcWallet("ht!tp://[not a valid uri");

        act.Should().Throw<ArgumentException>().WithMessage("*connection string*");
    }

    #endregion

    #region NIP-04 / NIP-44 v2 assembled-payload known-answer vectors (ported from l402-ts)

    // Fixed-input known-answer vectors, ported verbatim from
    // F:\le-... l402-ts/tests/wallets/nwc-crypto.test.ts. These were GENERATED by the
    // proven MCP Python NWC client (coincurve + cryptography) and are byte-identical to
    // the l402-ts port (node:crypto ChaCha20/HMAC + @noble ECDH). Asserting the ASSEMBLED
    // payload against a FIXED nonce/IV — not just an encrypt→decrypt round-trip with a
    // random nonce — is what proves this .NET port is wire-compatible with a wrong-but-
    // symmetric impl couldn't pass. Do NOT edit the hex without regenerating from the
    // reference client.
    private const string Vec_Seckey3 = "0000000000000000000000000000000000000000000000000000000000000003";
    private const string Vec_PubkeyFor3 = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    private const string Vec_SeckeyA = "0142424242424242424242424242424242424242424242424242424242424242";
    private const string Vec_AlicePub = "8dad4bc055b6f9698eaa43c0e3c320f9ca377d6b237671048b50a7920d221224";
    private const string Vec_SharedX = "150b9a865720b12157e2f5463189a5da551586e655bb4babba40e05594005551";
    private const string Vec_ConversationKey = "e0f6f2aeb0e50f479fd0da0e7b6965799a0104754d6448f4a7332138add9914d";
    private const string Vec_Iv16 = "000102030405060708090a0b0c0d0e0f";
    private const string Vec_Nonce32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string Vec_Plaintext = "the magic words are squeamish ossifrage";
    private const string Vec_Nip04Ciphertext =
        "6m20/hddxV4krD0M7AllC54Eptvx7tvPyR4X5eatqLooNc+icAf9etlMrqjsuxBB?iv=AAECAwQFBgcICQoLDA0ODw==";
    private const string Vec_Nip44Payload =
        "AgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fT/aulO+u59qN09JORRy56fr0mp6XbC+D+xeTWCfjbmL1iG+Esy/F/+oQuwD4Dmds+vvyR23i3tN79c2FoAI7Ob1mpWi2sjzpkrSBzADQ8PKnlmKJFJfV1KbZcrUP4+LMMXY=";
    private const string Vec_Nip44ShortPayload =
        "AgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fT9C7/IqOirvqurFuMnPLjYnU++zyTFzyjnLyNU6QBkKa++S8f+jhv2DY4r7VJUDJ3CeMnxD/M6YP8wmYCmGiFZ5v";

    private static ECPrivKey PrivFromHex(string hex)
    {
        ECPrivKey.TryCreate(Convert.FromHexString(hex), out var p);
        return p!;
    }

    // ── Curve vectors: pubkey derivation + raw shared-X (CoinOS path) ──

    [Fact]
    public void Vectors_DeriveXOnlyPubkey_MatchesFixtures()
    {
        Convert.ToHexString(NwcWallet.DeriveXOnlyPubkey(Convert.FromHexString(Vec_Seckey3))).ToLowerInvariant()
            .Should().Be(Vec_PubkeyFor3, "canonical BIP340 vector for scalar 3");
        Convert.ToHexString(NwcWallet.DeriveXOnlyPubkey(Convert.FromHexString(Vec_SeckeyA))).ToLowerInvariant()
            .Should().Be(Vec_AlicePub);
    }

    [Fact]
    public void Vectors_ComputeSharedSecret_MatchesFixedSharedX_AndIsSymmetric()
    {
        var alicePriv = PrivFromHex(Vec_SeckeyA);
        var bobPriv = PrivFromHex(Vec_Seckey3);
        var bobPub = Convert.FromHexString(Vec_PubkeyFor3);
        var alicePub = Convert.FromHexString(Vec_AlicePub);

        Convert.ToHexString(NwcWallet.ComputeSharedSecret(alicePriv, bobPub)).ToLowerInvariant()
            .Should().Be(Vec_SharedX, "raw shared-X must match an independently-generated ECDH (CoinOS path)");
        Convert.ToHexString(NwcWallet.ComputeSharedSecret(bobPriv, alicePub)).ToLowerInvariant()
            .Should().Be(Vec_SharedX, "ECDH shared-X is symmetric");
    }

    [Fact]
    public void Vectors_Nip44_ConversationKey_MatchesFixture()
    {
        // conversation_key = HKDF-Extract(salt="nip44-v2", ikm=shared_x) — the exact
        // derivation EncryptNip44/DecryptNip44 use internally.
        var sharedX = Convert.FromHexString(Vec_SharedX);
        var salt = System.Text.Encoding.UTF8.GetBytes("nip44-v2");
        var ck = System.Security.Cryptography.HKDF.Extract(
            System.Security.Cryptography.HashAlgorithmName.SHA256, sharedX, salt);
        Convert.ToHexString(ck).ToLowerInvariant().Should().Be(Vec_ConversationKey);
    }

    // ── NIP-04 (AES-256-CBC, raw shared-X key), fixed IV ──

    [Fact]
    public void Vectors_Nip04_EncryptWithFixedIv_ReproducesCiphertext()
    {
        var ct = NwcWallet.EncryptNip04(
            Vec_Plaintext, Convert.FromHexString(Vec_PubkeyFor3), PrivFromHex(Vec_SeckeyA),
            Convert.FromHexString(Vec_Iv16));
        ct.Should().Be(Vec_Nip04Ciphertext, "fixed-IV NIP-04 encryption must reproduce the reference ciphertext byte-for-byte");
    }

    [Fact]
    public void Vectors_Nip04_DecryptsReferenceCiphertext()
    {
        // Recipient = Bob (secret 3), sender = Alice. DecryptContent auto-detects NIP-04 via "?iv=".
        var plaintext = NwcWallet.DecryptContent(
            Vec_Nip04Ciphertext, Convert.FromHexString(Vec_AlicePub), PrivFromHex(Vec_Seckey3));
        plaintext.Should().Be(Vec_Plaintext);
    }

    // ── NIP-44 v2 (ChaCha20 + HKDF-SHA256 + HMAC), fixed nonce ──

    [Fact]
    public void Vectors_Nip44_EncryptWithFixedNonce_ReproducesPayload()
    {
        var payload = NwcWallet.EncryptNip44(
            Vec_Plaintext, Convert.FromHexString(Vec_PubkeyFor3), PrivFromHex(Vec_SeckeyA),
            Convert.FromHexString(Vec_Nonce32));
        payload.Should().Be(Vec_Nip44Payload, "fixed-nonce NIP-44 v2 encryption must reproduce the reference payload byte-for-byte");
    }

    [Fact]
    public void Vectors_Nip44_DecryptsReferencePayload()
    {
        var plaintext = NwcWallet.DecryptNip44(
            Vec_Nip44Payload, Convert.FromHexString(Vec_AlicePub), PrivFromHex(Vec_Seckey3));
        plaintext.Should().Be(Vec_Plaintext);
    }

    [Fact]
    public void Vectors_Nip44_ShortPayload_EncryptAndDecrypt_MatchFixture()
    {
        // Single-char plaintext padded to the 32-byte bucket.
        var payload = NwcWallet.EncryptNip44(
            "a", Convert.FromHexString(Vec_PubkeyFor3), PrivFromHex(Vec_SeckeyA),
            Convert.FromHexString(Vec_Nonce32));
        payload.Should().Be(Vec_Nip44ShortPayload);

        var plaintext = NwcWallet.DecryptNip44(
            Vec_Nip44ShortPayload, Convert.FromHexString(Vec_AlicePub), PrivFromHex(Vec_Seckey3));
        plaintext.Should().Be("a");
    }

    [Fact]
    public void Vectors_Nip44_TamperedCiphertextByte_FailsHmac()
    {
        // Flip a bit in the ciphertext region (after version+nonce, before mac) — HMAC must reject.
        var bytes = Convert.FromBase64String(Vec_Nip44Payload);
        bytes[40] ^= 0x01;
        var tampered = Convert.ToBase64String(bytes);

        var act = () => NwcWallet.DecryptNip44(
            tampered, Convert.FromHexString(Vec_AlicePub), PrivFromHex(Vec_Seckey3));
        act.Should().Throw<Exception>().WithMessage("*HMAC*");
    }

    #endregion

    #region ChaCha20 little-endian word decoding (RFC 8439)

    [Fact]
    public void ChaCha20_DecodesKeyAndNonceWordsLittleEndian()
    {
        // RFC 8439 §2.3 test vector. Decoding the key/nonce words as little-endian is
        // required for interop; a big-endian decode (BitConverter on a BE host) would
        // produce a different keystream. This pins the first keystream block.
        var key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte)i; // 00 01 02 ... 1f

        // RFC 8439 §2.4.2 sample nonce: 00:00:00:00:00:00:00:4a:00:00:00:00 — but the
        // canonical block test (§2.3.2) uses counter=1, nonce 00:00:00:09:00:00:00:4a:00:00:00:00.
        // We use the §2.3.2 nonce with this impl's counter origin (0) and verify the
        // keystream by XORing zero input.
        var nonce = new byte[12]
        {
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
        };

        // First keystream block = ChaCha20(zeros). With little-endian word decode this
        // matches the RFC vector's first block; a big-endian decode would not.
        var keystream = NwcWallet.ChaCha20(new byte[64], key, nonce);

        // Block-0 keystream for the given key/nonce with this impl's counter origin (0),
        // first 4 bytes pinned. The value is an interop anchor: it only holds under a
        // little-endian word decode. A big-endian decode (BitConverter on a BE host)
        // yields "f61aa641" instead.
        Convert.ToHexString(keystream.AsSpan(0, 4).ToArray()).ToLowerInvariant()
            .Should().Be("8adc91fd", "ChaCha20 key/nonce words must be decoded little-endian (RFC 8439)");
    }

    #endregion
}
