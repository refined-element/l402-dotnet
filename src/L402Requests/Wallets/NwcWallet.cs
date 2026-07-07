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
/// Allowed values for the NWC outbound encryption mode. Centralized so callers don't
/// duplicate magic strings. Mirrors the MCP server's <c>NwcEncryption</c>.
/// </summary>
public static class NwcEncryption
{
    /// <summary>
    /// NIP-04 — original NIP-47 encryption (ECDH + raw-shared-X + AES-256-CBC).
    /// Compatible with Primal NWC, CoinOS, Mutiny, ZBD, and most deployed wallets.
    /// Not accepted by Alby Hub.
    /// </summary>
    public const string Nip04 = "nip04";

    /// <summary>
    /// NIP-44 v2 — newer encryption (ECDH + HKDF-SHA256 + ChaCha20 + HMAC-SHA256).
    /// Required by Alby Hub. Silently dropped by older wallets, which surfaces as a
    /// no-response timeout — the original motivation for adding auto-detect.
    /// </summary>
    public const string Nip44V2 = "nip44_v2";

    /// <summary>
    /// Auto — fetch the wallet's NIP-47 INFO event (kind 13194) on the first pay,
    /// read the <c>encryption</c> tag, and pick <see cref="Nip44V2"/> if advertised
    /// (more secure) else <see cref="Nip04"/>. Cached for the lifetime of the wallet
    /// instance. Falls back to <see cref="Nip04"/> if the INFO event can't be fetched
    /// within a short deadline — older wallets that don't publish 13194 still work
    /// because NIP-04 is the original NIP-47 default.
    /// </summary>
    public const string Auto = "auto";

    /// <summary>
    /// Default outbound encryption mode. <see cref="Auto"/> means zero-config for every
    /// spec-compliant wallet — Primal/CoinOS/Mutiny/ZBD/Alby Hub all just work.
    /// </summary>
    public const string Default = Auto;

    public static bool IsValid(string? value) =>
        value == Nip04 || value == Nip44V2 || value == Auto;

    /// <summary>Comma-separated list of all valid values, for user-facing warnings.</summary>
    public static string AllowedValuesCsv => $"{Auto}, {Nip04}, {Nip44V2}";
}

/// <summary>
/// Pay invoices via Nostr Wallet Connect (NIP-47).
/// Connection string format: nostr+walletconnect://&lt;pubkey&gt;?relay=&lt;relay&gt;&amp;secret=&lt;secret&gt;
/// Compatible with: CoinOS, CLINK, Alby Hub, Primal, and other NWC wallets.
///
/// Cryptography (BIP340 schnorr signing + secp256k1 ECDH for NIP-04/44 encryption)
/// is provided by <c>NBitcoin.Secp256k1</c>, mirroring the implementation in the
/// Lightning Enable MCP server's <c>NwcWalletService</c>.
///
/// <para>
/// Outbound encryption defaults to <c>"auto"</c>: on the first pay the wallet's NIP-47
/// INFO event (kind 13194) is fetched and the strongest advertised scheme is used
/// (NIP-44 v2 if listed, else NIP-04), falling back to NIP-04 if no INFO event is
/// available. This is what makes payments to NIP-44-only wallets (e.g. Alby Hub) work —
/// a hard-coded NIP-04 request to such a wallet is undecryptable, so the wallet never
/// replies and the pay times out silently. Override via the constructor's
/// <c>encryption</c> parameter or the <c>NWC_ENCRYPTION</c> env var
/// (<c>auto</c> | <c>nip04</c> | <c>nip44_v2</c>). Inbound responses are always
/// auto-detected (<c>?iv=</c> ⇒ NIP-04, otherwise NIP-44 v2) regardless of this setting.
/// </para>
/// </summary>
public sealed class NwcWallet : IWallet, IDisposable
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

    // Configured outbound encryption mode ("auto" | "nip04" | "nip44_v2"). "auto"
    // resolves once per instance via the wallet's NIP-47 INFO event; see _resolvedAutoEncryption.
    private readonly string _encryption;

    // Auto-detect cache. When _encryption == "auto", the first pay triggers a one-time
    // fetch of the wallet's NIP-47 INFO event (kind 13194); the resolved scheme
    // ("nip04" or "nip44_v2") is stored here and reused for the lifetime of the instance.
    // The lock serialises concurrent first-request fetches.
    private string? _resolvedAutoEncryption;
    private readonly SemaphoreSlim _autoResolveLock = new(1, 1);
    private bool _disposed;

    /// <summary>
    /// How long to wait for the NIP-47 INFO event before falling back to NIP-04.
    /// Kept short so a missing/stale relay never delays a real pay by more than a
    /// few seconds. Internal so tests can override.
    /// </summary>
    internal static TimeSpan AutoResolveTimeout = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Test-only instrumentation. Incremented each time the INFO-event fetcher is actually
    /// invoked (NOT when the cache short-circuits), so cache tests can assert this stays
    /// at 1 across multiple resolve calls instead of relying on wall-clock timing.
    /// </summary>
    internal int InfoEventFetchCount;

    public string Name => "NWC";
    public bool SupportsPreimage => true;

    /// <summary>Configured outbound encryption mode ("auto" | "nip04" | "nip44_v2").</summary>
    internal string ConfiguredEncryption => _encryption;

    /// <param name="connectionString">nostr+walletconnect:// URI.</param>
    /// <param name="timeout">Per-pay receive timeout. Defaults to 60s.</param>
    /// <param name="encryption">
    /// Outbound encryption mode: <c>auto</c> (default), <c>nip04</c>, or <c>nip44_v2</c>.
    /// When null, the <c>NWC_ENCRYPTION</c> env var is consulted; an invalid/absent value
    /// falls back to <see cref="NwcEncryption.Default"/> (<c>auto</c>).
    /// </param>
    public NwcWallet(string connectionString, TimeSpan? timeout = null, string? encryption = null)
    {
        _timeout = timeout ?? TimeSpan.FromSeconds(60);

        // Resolve the outbound encryption mode: explicit param wins, then NWC_ENCRYPTION
        // env var, then the "auto" default. Invalid values fall back to the default rather
        // than throwing, so a typo can't silently break a previously-working wallet.
        var requested = encryption;
        if (string.IsNullOrWhiteSpace(requested))
            requested = Environment.GetEnvironmentVariable("NWC_ENCRYPTION");
        var normalized = requested?.Trim().ToLowerInvariant();
        _encryption = NwcEncryption.IsValid(normalized) ? normalized! : NwcEncryption.Default;

        // A malformed connection string makes `new Uri(...)` throw UriFormatException (a
        // FormatException, NOT an ArgumentException). Surface it as ArgumentException so the
        // constructor's error contract stays consistent with the missing-field validation below.
        Uri uri;
        try
        {
            uri = new Uri(connectionString);
        }
        catch (UriFormatException ex)
        {
            throw new ArgumentException("NWC connection string is not a valid URI", ex);
        }

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
        byte[] walletPubkeyBytes;
        try
        {
            walletPubkeyBytes = Convert.FromHexString(_walletPubkey);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("NWC connection string wallet pubkey is not valid hex", ex);
        }

        // A wallet pubkey is a 32-byte (64 hex char) secp256k1 x-only key. An even-length
        // hex string of the wrong size passes the hex check above but is not a valid pubkey;
        // it would otherwise slip through construction and only fail much later (ECDH lift /
        // receive timeout). Reject it up front with a clear message.
        if (walletPubkeyBytes.Length != 32)
            throw new ArgumentException(
                $"NWC connection string wallet pubkey must be 32 bytes (64 hex chars), got {walletPubkeyBytes.Length} bytes");

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
        // Resolve the outbound encryption scheme. "auto" (the default) fetches the wallet's
        // NIP-47 INFO event (kind 13194) once and caches the choice; explicit "nip04"/"nip44_v2"
        // skip the fetch. This is the fix for NIP-44-only wallets (e.g. Alby Hub): a hard-coded
        // NIP-04 request is undecryptable by such a wallet, which then never replies and the pay
        // times out silently. Inbound decryption still auto-detects, so this only affects outbound.
        var effectiveEncryption = _encryption == NwcEncryption.Auto
            ? await ResolveAutoEncryptionAsync(ct)
            : _encryption;

        // Build the signed, encrypted pay_invoice request event using the resolved scheme.
        var (nostrEvent, createdAt) = BuildPayInvoiceRequest(bolt11, effectiveEncryption);
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

                JsonDocument resultDoc;
                try
                {
                    resultDoc = JsonDocument.Parse(decrypted);
                }
                catch (JsonException)
                {
                    // Decrypted to something that isn't valid JSON — treat as not-for-us and
                    // keep waiting, matching how an undecryptable message is handled above.
                    // Never let a raw JsonException escape PayInvoiceAsync.
                    continue;
                }
                using (resultDoc)
                {
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
            }

            // Connect succeeded but the wallet never sent a matching reply within the timeout.
            // The most common cause is an encryption mismatch — Alby Hub silently drops NIP-04;
            // Primal/CoinOS silently drop NIP-44 v2 — so name the scheme we used and the swap hint.
            throw new PaymentFailedException(BuildTimeoutMessage(effectiveEncryption), bolt11);
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
    /// Builds the signed kind-23194 (NIP-47 request) event for a pay_invoice call using
    /// the given outbound encryption scheme.
    /// <list type="bullet">
    ///   <item><c>nip44_v2</c> — NIP-44 v2 encrypted content plus an
    ///   <c>["encryption","nip44_v2"]</c> tag (required so Alby-Hub-style wallets decrypt it).</item>
    ///   <item>anything else (<c>nip04</c>) — NIP-04 encrypted content with no encryption tag
    ///   (the absence of the tag is the original NIP-47 NIP-04 default).</item>
    /// </list>
    /// </summary>
    private (JsonObject Event, long CreatedAt) BuildPayInvoiceRequest(string bolt11, string encryption)
    {
        var requestContent = new JsonObject
        {
            ["method"] = "pay_invoice",
            ["params"] = new JsonObject { ["invoice"] = bolt11 }
        }.ToJsonString(NostrJsonOptions);

        var walletPubkeyBytes = Convert.FromHexString(_walletPubkey);

        string encryptedContent;
        JsonArray tags;
        if (encryption == NwcEncryption.Nip44V2)
        {
            encryptedContent = EncryptNip44(requestContent, walletPubkeyBytes, _privateKey);
            tags = new JsonArray
            {
                new JsonArray { "p", _walletPubkey },
                new JsonArray { "encryption", "nip44_v2" }
            };
        }
        else
        {
            encryptedContent = EncryptNip04(requestContent, walletPubkeyBytes, _privateKey);
            // No "encryption" tag — its absence is the original NIP-47 NIP-04 default.
            tags = new JsonArray { new JsonArray { "p", _walletPubkey } };
        }

        var createdAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

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
    /// Test seam: exposes <see cref="BuildPayInvoiceRequest"/> so unit tests can assert the
    /// outbound event's encryption/tagging and signature without a relay. Defaults to NIP-04
    /// for offline tests; the live default resolves via <c>auto</c> against the wallet.
    /// </summary>
    internal (JsonObject Event, long CreatedAt) BuildPayInvoiceRequestForTest(
        string bolt11, string encryption = NwcEncryption.Nip04)
        => BuildPayInvoiceRequest(bolt11, encryption);

    /// <summary>
    /// User-facing timeout message that names the scheme actually used and the swap hint,
    /// so an encryption mismatch (the most common silent-no-response cause) is diagnosable.
    /// </summary>
    private string BuildTimeoutMessage(string effectiveEncryption)
    {
        var alt = effectiveEncryption == NwcEncryption.Nip44V2 ? NwcEncryption.Nip04 : NwcEncryption.Nip44V2;
        return $"NWC payment timed out: wallet did not respond within {_timeout.TotalSeconds:0}s " +
               $"using {effectiveEncryption} encryption. Most common cause is an encryption mismatch — " +
               $"set NWC_ENCRYPTION={alt} (or pass encryption: \"{alt}\") if your wallet " +
               $"(e.g. Alby Hub needs nip44_v2; Primal/CoinOS need nip04) requires the other scheme.";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Outbound encryption auto-detect via the wallet's NIP-47 INFO event (kind 13194).
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Picks the strongest encryption scheme advertised in the NIP-47 INFO event's
    /// <c>encryption</c> tag (a space/comma-separated list, e.g. <c>"nip04 nip44_v2"</c>).
    /// Prefers <see cref="NwcEncryption.Nip44V2"/> when listed; otherwise NIP-04; falls back
    /// to NIP-04 for an empty/missing/unknown tag (the original NIP-47 default). Pure so it
    /// can be unit-tested without a relay.
    /// </summary>
    internal static string PickEncryptionFromInfoTag(string? encryptionTagValue)
    {
        if (string.IsNullOrWhiteSpace(encryptionTagValue))
            return NwcEncryption.Nip04;

        var schemes = encryptionTagValue
            .Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => s.ToLowerInvariant())
            .ToHashSet();

        if (schemes.Contains(NwcEncryption.Nip44V2)) return NwcEncryption.Nip44V2;
        if (schemes.Contains(NwcEncryption.Nip04)) return NwcEncryption.Nip04;
        return NwcEncryption.Nip04;
    }

    /// <summary>
    /// Resolves the outbound encryption scheme by fetching the wallet's NIP-47 INFO event
    /// (kind 13194), caching the result on the instance. On any failure (relay unreachable,
    /// timeout, malformed/forged event) falls back to <see cref="NwcEncryption.Nip04"/>.
    /// Concurrent first calls are serialised so we don't open N relay connections at startup.
    /// </summary>
    internal async Task<string> ResolveAutoEncryptionAsync(CancellationToken ct)
    {
        if (_resolvedAutoEncryption != null)
            return _resolvedAutoEncryption;

        await _autoResolveLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_resolvedAutoEncryption != null)
                return _resolvedAutoEncryption;

            var resolved = await FetchEncryptionFromInfoEventAsync(ct).ConfigureAwait(false);
            _resolvedAutoEncryption = resolved;
            return resolved;
        }
        finally
        {
            _autoResolveLock.Release();
        }
    }

    /// <summary>
    /// One-shot WebSocket REQ for the wallet's kind-13194 (NIP-47 INFO) event, reads the
    /// <c>encryption</c> tag, and returns the picked scheme. Always returns a value —
    /// exceptions and timeouts translate to the NIP-04 fallback. The event's pubkey and
    /// BIP340 signature are verified first, so a malicious relay can't forge an INFO event
    /// to force an encryption downgrade.
    /// </summary>
    private async Task<string> FetchEncryptionFromInfoEventAsync(CancellationToken ct)
    {
        Interlocked.Increment(ref InfoEventFetchCount);

        using var ws = new ClientWebSocket();
        try
        {
            using var timeout = new CancellationTokenSource(AutoResolveTimeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);

            await ws.ConnectAsync(new Uri(_relay), linked.Token).ConfigureAwait(false);

            var subId = Guid.NewGuid().ToString("N")[..16];
            var reqMessage = new JsonArray
            {
                "REQ",
                subId,
                new JsonObject
                {
                    ["kinds"] = new JsonArray { 13194 },
                    ["authors"] = new JsonArray { _walletPubkey },
                    ["limit"] = 1
                }
            };
            await SendTextAsync(ws, reqMessage.ToJsonString(NostrJsonOptions), linked.Token).ConfigureAwait(false);

            var buffer = new byte[8192];
            var sb = new StringBuilder();
            while (ws.State == WebSocketState.Open)
            {
                var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), linked.Token).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close) break;
                if (result.MessageType != WebSocketMessageType.Text)
                {
                    sb.Clear();
                    continue;
                }
                sb.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                if (!result.EndOfMessage) continue;

                var message = sb.ToString();
                sb.Clear();

                JsonArray? parsed;
                try { parsed = JsonNode.Parse(message)?.AsArray(); }
                catch (JsonException) { continue; }
                if (parsed == null || parsed.Count < 2) continue;

                var msgType = parsed[0]?.GetValue<string>();
                if (msgType == "EVENT" && parsed.Count >= 3)
                {
                    // Ignore events for other subscriptions.
                    if (parsed[1]?.GetValue<string>() != subId) continue;

                    var ev = parsed[2]?.AsObject();
                    if (ev?["kind"]?.GetValue<int>() != 13194) continue;

                    // Verify author + BIP340 signature before trusting the encryption tag —
                    // otherwise a relay could forge a 13194 event to force a downgrade/DoS.
                    if (!IsResponseEventTrustworthy(ev, _walletPubkey, out _)) continue;

                    var encTagValue = ev["tags"]?.AsArray()
                        .Select(t => t?.AsArray())
                        .Where(t => t != null && t.Count >= 2 && t[0]?.GetValue<string>() == "encryption")
                        .Select(t => t![1]?.GetValue<string>())
                        .FirstOrDefault();
                    return PickEncryptionFromInfoTag(encTagValue);
                }
                else if (msgType == "EOSE")
                {
                    if (parsed[1]?.GetValue<string>() != subId) continue;
                    // No INFO event in stored history — older wallet that never published
                    // 13194. Fall back to NIP-04.
                    return NwcEncryption.Nip04;
                }
            }

            return NwcEncryption.Nip04;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Caller cancellation propagates untouched.
            throw;
        }
        catch (OperationCanceledException)
        {
            // Internal AutoResolveTimeout fired; safe fallback.
            return NwcEncryption.Nip04;
        }
        catch
        {
            // Relay unreachable / malformed data — safe fallback.
            return NwcEncryption.Nip04;
        }
        finally
        {
            if (ws.State == WebSocketState.Open)
            {
                try
                {
                    using var closeCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, closeCts.Token).ConfigureAwait(false);
                }
                catch { ws.Abort(); }
            }
        }
    }

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
        var iv = new byte[16];
        RandomNumberGenerator.Fill(iv);
        return EncryptNip04(plaintext, recipientPubkeyBytes, senderPrivKey, iv);
    }

    /// <summary>
    /// Deterministic overload with an explicit 16-byte IV. Used by known-answer tests to
    /// reproduce a fixed ciphertext byte-for-byte; production callers use the random-IV
    /// overload above. The crypto is identical — only the IV source differs.
    /// </summary>
    internal static string EncryptNip04(string plaintext, byte[] recipientPubkeyBytes, ECPrivKey senderPrivKey, byte[] iv)
    {
        var sharedX = ComputeSharedSecret(senderPrivKey, recipientPubkeyBytes);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

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
        var nonce = new byte[32];
        RandomNumberGenerator.Fill(nonce);
        return EncryptNip44(plaintext, recipientPubkeyBytes, senderPrivKey, nonce);
    }

    /// <summary>
    /// Deterministic overload with an explicit 32-byte nonce. Used by known-answer tests to
    /// reproduce a fixed NIP-44 payload byte-for-byte; production callers use the random-nonce
    /// overload above. The crypto is identical — only the nonce source differs.
    /// </summary>
    internal static string EncryptNip44(string plaintext, byte[] recipientPubkeyBytes, ECPrivKey senderPrivKey, byte[] nonce)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        if (plaintextBytes.Length < 1 || plaintextBytes.Length > 65535)
            throw new ArgumentException($"Plaintext length {plaintextBytes.Length} out of range (1-65535)");
        if (nonce.Length != 32)
            throw new ArgumentException("NIP-44 nonce must be 32 bytes", nameof(nonce));

        var sharedX = ComputeSharedSecret(senderPrivKey, recipientPubkeyBytes);

        var salt = Encoding.UTF8.GetBytes("nip44-v2");
        var conversationKey = HKDF.Extract(HashAlgorithmName.SHA256, sharedX, salt);

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

    public void Dispose()
    {
        if (_disposed) return;
        // SemaphoreSlim is IDisposable — release its wait handle explicitly. Matters for
        // long-running processes that recreate the wallet (e.g. config reload).
        _autoResolveLock.Dispose();
        _disposed = true;
    }
}
