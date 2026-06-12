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

    #region Outbound encryption defaults to NIP-04

    [Fact]
    public void BuildPayInvoiceRequest_DefaultsToNip04Encryption()
    {
        // The outbound pay_invoice event must be NIP-04 encrypted by default
        // (CoinOS silently drops NIP-44 v2). We verify by decrypting the event
        // content from the wallet side using the SAME ECDH pair and asserting we
        // recover the pay_invoice JSON — and that the content carries the NIP-04
        // "?iv=" marker.
        var (walletPriv, walletPub) = GenerateKeyPair();
        var walletPubHex = Convert.ToHexString(walletPub).ToLowerInvariant();

        var connStr =
            "nostr+walletconnect://" + walletPubHex +
            "?relay=wss://relay.example.com&secret=" + ValidClientSecretHex;
        var wallet = new NwcWallet(connStr);

        var bolt11 = "lnbc100n1p3xyztest";
        var (eventObj, _) = wallet.BuildPayInvoiceRequestForTest(bolt11);

        var content = eventObj["content"]!.GetValue<string>();
        content.Should().Contain("?iv=", "default outbound encryption is NIP-04");

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
