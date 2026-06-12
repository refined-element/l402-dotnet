using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using NBitcoin.Secp256k1;

namespace L402Requests.Wallets;

/// <summary>
/// Pay invoices via Nostr Wallet Connect (NIP-47).
/// Connection string format: nostr+walletconnect://&lt;pubkey&gt;?relay=&lt;relay&gt;&amp;secret=&lt;secret&gt;
/// Compatible with: CoinOS, CLINK, Alby, and other NWC wallets.
///
/// Cryptography (BIP340 schnorr signing + secp256k1 ECDH for NIP-04/44 encryption)
/// is provided by <c>NBitcoin.Secp256k1</c>, mirroring the implementation in the
/// Lightning Enable MCP server's <c>NwcWalletService</c>.
/// </summary>
public sealed class NwcWallet : IWallet
{
    // Relaxed JSON escaping for the canonical Nostr serialisation. The default
    // System.Text.Json encoder escapes HTML-sensitive and non-ASCII characters (such as
    // less-than, greater-than, ampersand and plus) into their backslash-u unicode escape
    // form. UnsafeRelaxedJsonEscaping emits them as the literal character instead, which
    // is what other Nostr implementations produce when computing the event id (SHA256
    // over the serialised array). Any escaping difference would change the bytes hashed
    // and yield a mismatched event id that relays/wallets reject, so this encoder must be
    // used here.
    private static readonly JsonSerializerOptions NostrJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        // Required on net8.0: serialising JsonNode primitives (the literal 0, numbers,
        // etc.) with custom options throws unless a type-info resolver is present.
        TypeInfoResolver = new DefaultJsonTypeInfoResolver()
    };

    private readonly string _walletPubkey;        // wallet x-only pubkey (hex)
    private readonly string _relay;
    private readonly byte[] _secretBytes;         // client secret (32-byte scalar)
    private readonly ECPrivKey _privateKey;       // client private key
    private readonly string _myPubkeyHex;         // client x-only pubkey (hex)
    private readonly TimeSpan _timeout;

    public string Name => "NWC";
    public bool SupportsPreimage => true;

    public NwcWallet(string connectionString, TimeSpan? timeout = null)
    {
        _timeout = timeout ?? TimeSpan.FromSeconds(30);

        var uri = new Uri(connectionString);
        _walletPubkey = uri.Host;

        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        _relay = query["relay"] ?? throw new ArgumentException("NWC connection string missing relay URL");
        var secret = query["secret"] ?? throw new ArgumentException("NWC connection string missing secret");

        if (string.IsNullOrEmpty(_walletPubkey))
            throw new ArgumentException("NWC connection string missing wallet pubkey");

        // Validate the wallet pubkey is well-formed hex up front. Convert.FromHexString
        // throws FormatException for malformed input, which would otherwise bubble out of
        // the constructor as an unexpected type — surface it as ArgumentException so the
        // connection-string error contract is consistent (matches missing-relay/secret).
        try
        {
            _ = Convert.FromHexString(_walletPubkey);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("NWC connection string wallet pubkey is not valid hex", ex);
        }

        try
        {
            _secretBytes = Convert.FromHexString(secret);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("NWC connection string secret is not valid hex", ex);
        }

        if (!ECPrivKey.TryCreate(_secretBytes, out var privKey) || privKey is null)
            throw new ArgumentException("NWC connection string secret is not a valid secp256k1 private key");
        _privateKey = privKey;
        _myPubkeyHex = Convert.ToHexString(privKey.CreateXOnlyPubKey().ToBytes()).ToLowerInvariant();
    }

    public async Task<string> PayInvoiceAsync(string bolt11, CancellationToken ct = default)
    {
        // Build the signed, NIP-04 encrypted pay_invoice request event.
        var (nostrEvent, createdAt) = BuildPayInvoiceRequest(bolt11);
        var eventId = nostrEvent["id"]!.GetValue<string>();

        using var ws = new ClientWebSocket();
        await ws.ConnectAsync(new Uri(_relay), ct);

        try
        {
            // Subscribe for the response (kind 23195) BEFORE publishing the request,
            // scoped to our request event id (#e) so we only see our own reply.
            var subId = Guid.NewGuid().ToString("N")[..16];
            var subMsg = new JsonArray
            {
                "REQ", subId, new JsonObject
                {
                    ["kinds"] = new JsonArray { 23195 },
                    ["authors"] = new JsonArray { _walletPubkey },
                    ["#p"] = new JsonArray { _myPubkeyHex },
                    ["#e"] = new JsonArray { eventId },
                    ["since"] = createdAt - 1
                }
            };
            await SendTextAsync(ws, subMsg.ToJsonString(NostrJsonOptions), ct);

            // Publish the pay request.
            var eventMsg = new JsonArray { "EVENT", JsonNode.Parse(nostrEvent.ToJsonString(NostrJsonOptions)) };
            await SendTextAsync(ws, eventMsg.ToJsonString(NostrJsonOptions), ct);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(_timeout);

            var sb = new StringBuilder();
            var buffer = new byte[8192];

            while (!timeoutCts.Token.IsCancellationRequested && ws.State == WebSocketState.Open)
            {
                WebSocketReceiveResult result;
                try
                {
                    result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), timeoutCts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (result.MessageType == WebSocketMessageType.Close) break;
                // Nostr relay frames are UTF-8 text. Ignore Binary (or any non-Text,
                // non-Close) frames rather than decoding them as garbage UTF-8 and
                // feeding the JSON parser. Reset any partial buffer so a stray binary
                // fragment can't corrupt a subsequent text message.
                if (result.MessageType != WebSocketMessageType.Text)
                {
                    sb.Clear();
                    continue;
                }
                sb.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                if (!result.EndOfMessage) continue;

                var message = sb.ToString();
                sb.Clear();

                JsonArray? msgArray;
                try { msgArray = JsonNode.Parse(message)?.AsArray(); }
                catch (JsonException) { continue; }

                if (msgArray is null || msgArray.Count < 2) continue;
                if (msgArray[0]?.GetValue<string>() != "EVENT") continue;
                // Relay-message framing is ["EVENT", <subId>, <event>]. Only accept events
                // delivered for the subscription we opened — a relay could push unrelated
                // events on other subscriptions, which must not be mistaken for our reply.
                if (msgArray.Count < 3) continue;
                if (msgArray[1]?.GetValue<string>() != subId) continue;

                var responseEvent = msgArray[2]?.AsObject();
                if (responseEvent is null) continue;
                if (responseEvent["kind"]?.GetValue<int>() != 23195) continue;

                // F-11: cryptographically verify the response event before trusting its
                // (encrypted) content. Defence-in-depth on top of the NIP-04/44 ECDH
                // layer — rejects relay-forged events attributed to the wallet pubkey
                // and any event whose author isn't the configured wallet.
                if (!IsResponseEventTrustworthy(responseEvent, _walletPubkey, out _))
                    continue;

                // Confirm this reply is for our specific request (#e tag), when present.
                var responseETag = responseEvent["tags"]?.AsArray()
                    ?.Where(t => t?.AsArray()?.Count >= 2 && t![0]?.GetValue<string>() == "e")
                    .Select(t => t![1]?.GetValue<string>())
                    .FirstOrDefault();
                if (responseETag != null && responseETag != eventId) continue;

                var encryptedContent = responseEvent["content"]?.GetValue<string>();
                if (string.IsNullOrEmpty(encryptedContent)) continue;

                // Inbound auto-detects NIP-04 vs NIP-44. Sender = response event author.
                var senderPubkeyHex = responseEvent["pubkey"]?.GetValue<string>() ?? _walletPubkey;
                var senderPubkeyBytes = Convert.FromHexString(senderPubkeyHex);

                string decrypted;
                try
                {
                    decrypted = DecryptContent(encryptedContent, senderPubkeyBytes, _privateKey);
                }
                catch
                {
                    // Couldn't decrypt — treat as not-for-us and keep waiting.
                    continue;
                }

                using var resultDoc = JsonDocument.Parse(decrypted);
                var root = resultDoc.RootElement;

                if (root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object)
                {
                    var code = error.TryGetProperty("code", out var c) ? c.ToString() : "unknown";
                    var errorMsg = error.TryGetProperty("message", out var m) ? m.GetString() ?? "unknown error" : "unknown error";
                    throw new PaymentFailedException($"NWC error {code}: {errorMsg}", bolt11);
                }

                if (root.TryGetProperty("result", out var resultObj) &&
                    resultObj.ValueKind == JsonValueKind.Object &&
                    resultObj.TryGetProperty("preimage", out var preimageEl))
                {
                    var preimage = preimageEl.GetString();
                    if (string.IsNullOrEmpty(preimage))
                        throw new PaymentFailedException("NWC payment succeeded but no preimage returned", bolt11);
                    return preimage;
                }
            }

            throw new PaymentFailedException("NWC payment timed out", bolt11);
        }
        finally
        {
            // Best-effort close. Use CloseOutputAsync (send-only) with a short bound so a
            // relay that never echoes the close handshake can't hang the call after we
            // already have the preimage. Fall back to Abort() on any failure.
            if (ws.State == WebSocketState.Open)
            {
                try
                {
                    using var closeCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, closeCts.Token);
                }
                catch
                {
                    ws.Abort();
                }
            }
        }
    }

    /// <summary>
    /// Builds the signed kind-23194 (NIP-47 request) event for a pay_invoice call.
    /// Outbound encryption defaults to NIP-04 — CoinOS silently drops NIP-44 v2, so
    /// NIP-04 is the compatible default for the outbound request.
    /// </summary>
    private (JsonObject Event, long CreatedAt) BuildPayInvoiceRequest(string bolt11)
    {
        var requestContent = new JsonObject
        {
            ["method"] = "pay_invoice",
            ["params"] = new JsonObject { ["invoice"] = bolt11 }
        }.ToJsonString(NostrJsonOptions);

        var walletPubkeyBytes = Convert.FromHexString(_walletPubkey);
        var encryptedContent = EncryptNip04(requestContent, walletPubkeyBytes, _privateKey);

        var createdAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // No "encryption" tag — its absence is the original NIP-47 NIP-04 default.
        var tags = new JsonArray { new JsonArray { "p", _walletPubkey } };

        var eventId = ComputeEventId(_myPubkeyHex, createdAt, 23194, tags, encryptedContent);
        var sig = SchnorrSign(_secretBytes, Convert.FromHexString(eventId));

        var nostrEvent = new JsonObject
        {
            ["id"] = eventId,
            ["pubkey"] = _myPubkeyHex,
            ["created_at"] = createdAt,
            ["kind"] = 23194,
            ["tags"] = JsonNode.Parse(tags.ToJsonString(NostrJsonOptions)),
            ["content"] = encryptedContent,
            ["sig"] = Convert.ToHexString(sig).ToLowerInvariant()
        };

        return (nostrEvent, createdAt);
    }

    /// <summary>
    /// Test seam: exposes <see cref="BuildPayInvoiceRequest"/> so unit tests can assert
    /// the outbound event is NIP-04 encrypted and correctly signed without a relay.
    /// </summary>
    internal (JsonObject Event, long CreatedAt) BuildPayInvoiceRequestForTest(string bolt11)
        => BuildPayInvoiceRequest(bolt11);

    private static async Task SendTextAsync(ClientWebSocket ws, string text, CancellationToken ct)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        await ws.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, ct);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // secp256k1 primitives (ported from MCP NwcWalletService)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Derives the 32-byte BIP340 x-only public key from a 32-byte private key.
    /// </summary>
    internal static byte[] DeriveXOnlyPubkey(byte[] privateKey)
    {
        if (!ECPrivKey.TryCreate(privateKey, out var privKey) || privKey is null)
            throw new ArgumentException("Invalid secp256k1 private key");
        return privKey.CreateXOnlyPubKey().ToBytes();
    }

    /// <summary>
    /// BIP340 schnorr-signs a 32-byte message hash (the Nostr event id) with the
    /// given 32-byte private key. Returns the 64-byte signature.
    /// </summary>
    internal static byte[] SchnorrSign(byte[] privateKey, byte[] messageHash)
    {
        if (!ECPrivKey.TryCreate(privateKey, out var privKey) || privKey is null)
            throw new ArgumentException("Invalid secp256k1 private key");
        if (!privKey.TrySignBIP340(messageHash, null, out var sig) || sig is null)
            throw new InvalidOperationException("BIP340 signing failed");
        return sig.ToBytes();
    }

    /// <summary>
    /// Computes the NIP-04/44 ECDH shared X-coordinate (32 bytes) between our private
    /// key and a counterparty x-only public key. Symmetric: A(privA, pubB) == B(privB, pubA).
    /// </summary>
    internal static byte[] ComputeSharedSecret(ECPrivKey privKey, byte[] counterpartyXOnlyPubkey)
    {
        // Lift the x-only pubkey to a full point (assume even y — NIP-04/44 convention).
        var fullPubkeyBytes = new byte[33];
        fullPubkeyBytes[0] = 0x02;
        counterpartyXOnlyPubkey.CopyTo(fullPubkeyBytes, 1);

        if (!ECPubKey.TryCreate(fullPubkeyBytes, Context.Instance, out _, out var counterpartyPubKey) || counterpartyPubKey is null)
            throw new ArgumentException("Invalid counterparty public key");

        var sharedPoint = counterpartyPubKey.GetSharedPubkey(privKey);
        return sharedPoint.ToBytes()[1..33]; // x-coordinate only
    }

    /// <summary>
    /// Computes the Nostr event id: SHA256 over the canonical serialised array
    /// [0, pubkey, created_at, kind, tags, content], using relaxed JSON escaping.
    /// </summary>
    internal static string ComputeEventId(string pubkey, long createdAt, int kind, JsonArray tags, string content)
    {
        var eventArray = new JsonArray
        {
            0, pubkey, createdAt, kind, JsonNode.Parse(tags.ToJsonString(NostrJsonOptions)), content
        };
        var serialized = eventArray.ToJsonString(NostrJsonOptions);
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(serialized));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Verifies a Nostr event's BIP340 schnorr signature against its claimed pubkey AND
    /// that the recomputed event id matches the claimed id. Returns false on any
    /// malformed input rather than throwing.
    /// </summary>
    internal static bool VerifyNostrEventSignature(JsonObject ev)
    {
        try
        {
            var idHex = ev["id"]?.GetValue<string>();
            var pubkeyHex = ev["pubkey"]?.GetValue<string>();
            var sigHex = ev["sig"]?.GetValue<string>();
            var createdAt = ev["created_at"]?.GetValue<long>();
            var kind = ev["kind"]?.GetValue<int>();
            var tags = ev["tags"]?.AsArray();
            var content = ev["content"]?.GetValue<string>();

            if (idHex == null || pubkeyHex == null || sigHex == null
                || createdAt == null || kind == null || tags == null || content == null)
                return false;
            if (idHex.Length != 64 || pubkeyHex.Length != 64 || sigHex.Length != 128)
                return false;

            // Recompute the id from the canonical serialisation; any post-sign tamper
            // (content, tags, etc.) changes the recomputed id and breaks the match.
            var recomputedId = ComputeEventId(pubkeyHex, createdAt.Value, kind.Value, tags, content);
            // Constant-time compare on the id (security material) — Standard #7.
            var recomputedBytes = Convert.FromHexString(recomputedId);
            var claimedBytes = Convert.FromHexString(idHex);
            if (!CryptographicOperations.FixedTimeEquals(recomputedBytes, claimedBytes))
                return false;

            var pubkeyBytes = Convert.FromHexString(pubkeyHex);
            var sigBytes = Convert.FromHexString(sigHex);
            var idBytes = Convert.FromHexString(idHex);

            if (!ECXOnlyPubKey.TryCreate(pubkeyBytes, out var pubkey) || pubkey == null)
                return false;
            if (!SecpSchnorrSignature.TryCreate(sigBytes, out var sig) || sig == null)
                return false;

            return pubkey.SigVerifyBIP340(sig, idBytes);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// F-11 gate for kind-23195 (NIP-47 response) events: rejects any event whose
    /// <c>pubkey</c> doesn't match the configured wallet OR whose BIP340 signature
    /// fails verification. Defence-in-depth on top of NIP-04/44 ECDH encryption.
    /// </summary>
    internal static bool IsResponseEventTrustworthy(JsonObject ev, string expectedWalletPubkey, out string rejectionReason)
    {
        var eventPubkey = ev["pubkey"]?.GetValue<string>();
        if (!string.Equals(eventPubkey, expectedWalletPubkey, StringComparison.OrdinalIgnoreCase))
        {
            var preview = eventPubkey != null
                ? eventPubkey[..Math.Min(16, eventPubkey.Length)] + "..."
                : "<null>";
            rejectionReason = $"pubkey mismatch ({preview})";
            return false;
        }

        if (!VerifyNostrEventSignature(ev))
        {
            rejectionReason = "BIP340 signature verification failed";
            return false;
        }

        rejectionReason = string.Empty;
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NIP-04 (ECDH + AES-256-CBC). Raw shared-X is the AES key — confirmed
    // compatible with CoinOS and the l402-ts client (see MCP NwcWalletService).
    // ─────────────────────────────────────────────────────────────────────────

    internal static string EncryptNip04(string plaintext, byte[] recipientPubkeyBytes, ECPrivKey senderPrivKey)
    {
        var sharedX = ComputeSharedSecret(senderPrivKey, recipientPubkeyBytes);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var iv = new byte[16];
        RandomNumberGenerator.Fill(iv);

        using var aes = Aes.Create();
        aes.Key = sharedX; // raw 32-byte X coordinate
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        var encrypted = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

        return Convert.ToBase64String(encrypted) + "?iv=" + Convert.ToBase64String(iv);
    }

    /// <summary>
    /// Auto-detects NIP-04 (has "?iv=") vs NIP-44 (single base64 blob) and dispatches.
    /// </summary>
    internal static string DecryptContent(string encryptedContent, byte[] senderPubkeyBytes, ECPrivKey recipientPrivKey)
    {
        return encryptedContent.Contains("?iv=")
            ? DecryptNip04(encryptedContent, senderPubkeyBytes, recipientPrivKey)
            : DecryptNip44(encryptedContent, senderPubkeyBytes, recipientPrivKey);
    }

    internal static string DecryptNip04(string ciphertext, byte[] senderPubkeyBytes, ECPrivKey recipientPrivKey)
    {
        var parts = ciphertext.Split("?iv=");
        if (parts.Length != 2)
            throw new InvalidOperationException("Invalid NIP-04 ciphertext format");

        var encryptedBytes = Convert.FromBase64String(parts[0]);
        var iv = Convert.FromBase64String(parts[1]);

        var sharedX = ComputeSharedSecret(recipientPrivKey, senderPubkeyBytes);

        using var aes = Aes.Create();
        aes.Key = sharedX; // raw 32-byte X coordinate
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        var decrypted = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
        return Encoding.UTF8.GetString(decrypted);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NIP-44 v2 (ECDH + HKDF-SHA256 + ChaCha20 + HMAC-SHA256).
    // ─────────────────────────────────────────────────────────────────────────

    internal static string EncryptNip44(string plaintext, byte[] recipientPubkeyBytes, ECPrivKey senderPrivKey)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        if (plaintextBytes.Length < 1 || plaintextBytes.Length > 65535)
            throw new ArgumentException($"Plaintext length {plaintextBytes.Length} out of range (1-65535)");

        var sharedX = ComputeSharedSecret(senderPrivKey, recipientPubkeyBytes);

        var salt = Encoding.UTF8.GetBytes("nip44-v2");
        var conversationKey = HKDF.Extract(HashAlgorithmName.SHA256, sharedX, salt);

        var nonce = new byte[32];
        RandomNumberGenerator.Fill(nonce);

        var messageKeys = new byte[76];
        HKDF.Expand(HashAlgorithmName.SHA256, conversationKey, messageKeys, nonce);

        var chachaKey = messageKeys[0..32];
        var chachaNonce = messageKeys[32..44];
        var hmacKey = messageKeys[44..76];

        var paddedLen = CalcPaddedLen(plaintextBytes.Length);
        var padded = new byte[2 + paddedLen];
        padded[0] = (byte)(plaintextBytes.Length >> 8);
        padded[1] = (byte)(plaintextBytes.Length & 0xFF);
        plaintextBytes.CopyTo(padded, 2);

        var ciphertext = ChaCha20(padded, chachaKey, chachaNonce);

        var hmacInput = new byte[nonce.Length + ciphertext.Length];
        nonce.CopyTo(hmacInput, 0);
        ciphertext.CopyTo(hmacInput, nonce.Length);
        using var hmac = new System.Security.Cryptography.HMACSHA256(hmacKey);
        var mac = hmac.ComputeHash(hmacInput);

        var payload = new byte[1 + nonce.Length + ciphertext.Length + mac.Length];
        payload[0] = 0x02;
        nonce.CopyTo(payload, 1);
        ciphertext.CopyTo(payload, 33);
        mac.CopyTo(payload, 33 + ciphertext.Length);

        return Convert.ToBase64String(payload);
    }

    internal static string DecryptNip44(string content, byte[] senderPubkeyBytes, ECPrivKey recipientPrivKey)
    {
        var data = Convert.FromBase64String(content);
        if (data.Length < 99)
            throw new InvalidOperationException("NIP-44 ciphertext too short");

        if (data[0] != 0x02)
            throw new InvalidOperationException($"Unsupported NIP-44 version: {data[0]}");

        var nonce = data[1..33];
        var ciphertext = data[33..^32];
        var mac = data[^32..];

        var sharedX = ComputeSharedSecret(recipientPrivKey, senderPubkeyBytes);

        var salt = Encoding.UTF8.GetBytes("nip44-v2");
        var conversationKey = HKDF.Extract(HashAlgorithmName.SHA256, sharedX, salt);

        var messageKeys = new byte[76];
        HKDF.Expand(HashAlgorithmName.SHA256, conversationKey, messageKeys, nonce);

        var chachaKey = messageKeys[0..32];
        var chachaNonce = messageKeys[32..44];
        var hmacKey = messageKeys[44..76];

        using var hmac = new System.Security.Cryptography.HMACSHA256(hmacKey);
        var hmacInput = new byte[nonce.Length + ciphertext.Length];
        nonce.CopyTo(hmacInput, 0);
        ciphertext.CopyTo(hmacInput, nonce.Length);
        var computedMac = hmac.ComputeHash(hmacInput);

        // Constant-time MAC comparison — Standard #7.
        if (!CryptographicOperations.FixedTimeEquals(computedMac, mac))
            throw new InvalidOperationException("NIP-44 HMAC verification failed");

        var decrypted = ChaCha20(ciphertext, chachaKey, chachaNonce);
        if (decrypted.Length < 2)
            throw new InvalidOperationException("NIP-44 decrypted data too short");

        var plaintextLength = (decrypted[0] << 8) | decrypted[1];
        if (plaintextLength <= 0 || 2 + plaintextLength > decrypted.Length)
            throw new InvalidOperationException($"NIP-44 invalid plaintext length: {plaintextLength}");

        return Encoding.UTF8.GetString(decrypted, 2, plaintextLength);
    }

    internal static int CalcPaddedLen(int unpaddedLen)
    {
        if (unpaddedLen <= 0) throw new ArgumentException("Length must be > 0");
        if (unpaddedLen <= 32) return 32;

        var nextPower = 1;
        var temp = unpaddedLen - 1;
        while (temp > 0) { nextPower <<= 1; temp >>= 1; }

        var chunk = Math.Max(32, nextPower >> 3);
        return chunk * ((unpaddedLen + chunk - 1) / chunk);
    }

    /// <summary>
    /// ChaCha20 stream cipher (IETF variant, RFC 8439). Raw stream cipher (NOT AEAD).
    /// 32-byte key, 12-byte nonce, counter starts at 0. Symmetric: applying twice = identity.
    /// </summary>
    internal static byte[] ChaCha20(byte[] input, byte[] key, byte[] nonce)
    {
        if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (nonce.Length != 12) throw new ArgumentException("Nonce must be 12 bytes", nameof(nonce));

        var output = new byte[input.Length];
        var state = new uint[16];
        var keyStream = new byte[64];
        uint counter = 0;

        // RFC 8439 requires little-endian decoding of the key/nonce words. BitConverter
        // is host-endianness-dependent (wrong on big-endian platforms), so decode the
        // words explicitly little-endian for deterministic, interop-correct output.
        var keyWords = new uint[8];
        for (int i = 0; i < 8; i++)
            keyWords[i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4));

        var nonceWords = new uint[3];
        for (int i = 0; i < 3; i++)
            nonceWords[i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(i * 4));

        for (int offset = 0; offset < input.Length; offset += 64)
        {
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            for (int i = 0; i < 8; i++) state[4 + i] = keyWords[i];

            state[12] = counter;
            state[13] = nonceWords[0];
            state[14] = nonceWords[1];
            state[15] = nonceWords[2];

            var initialState = (uint[])state.Clone();

            for (int i = 0; i < 10; i++)
            {
                QuarterRound(state, 0, 4, 8, 12);
                QuarterRound(state, 1, 5, 9, 13);
                QuarterRound(state, 2, 6, 10, 14);
                QuarterRound(state, 3, 7, 11, 15);

                QuarterRound(state, 0, 5, 10, 15);
                QuarterRound(state, 1, 6, 11, 12);
                QuarterRound(state, 2, 7, 8, 13);
                QuarterRound(state, 3, 4, 9, 14);
            }

            for (int i = 0; i < 16; i++) state[i] += initialState[i];

            for (int i = 0; i < 16; i++)
            {
                keyStream[i * 4] = (byte)(state[i]);
                keyStream[i * 4 + 1] = (byte)(state[i] >> 8);
                keyStream[i * 4 + 2] = (byte)(state[i] >> 16);
                keyStream[i * 4 + 3] = (byte)(state[i] >> 24);
            }

            var blockLen = Math.Min(64, input.Length - offset);
            for (int i = 0; i < blockLen; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keyStream[i]);

            counter++;
        }

        return output;
    }

    private static uint RotateLeft(uint v, int n) => (v << n) | (v >> (32 - n));

    private static void QuarterRound(uint[] s, int a, int b, int c, int d)
    {
        s[a] += s[b]; s[d] ^= s[a]; s[d] = RotateLeft(s[d], 16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = RotateLeft(s[b], 12);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = RotateLeft(s[d], 8);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = RotateLeft(s[b], 7);
    }
}
