using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using L402Requests.Wallets;
using NBitcoin.Secp256k1;

namespace L402Requests.Tests.Wallets;

/// <summary>
/// Minimal in-process Nostr relay that plays the NWC wallet side, for end-to-end
/// <see cref="NwcWallet.PayInvoiceAsync"/> tests without a real relay or wallet.
///
/// Behaviour: accepts a client connection, reads framed Nostr messages, and on the
/// kind-23194 EVENT it decrypts the request (NIP-04/44 auto-detect) using the
/// configured wallet private key, then publishes a signed, encrypted kind-23195
/// response carrying the supplied preimage. The response is tagged with the request
/// event id (#e) and signed by <see cref="_walletPubkeyHex"/> so it passes (or, when
/// the keys are an attacker's, fails) the client's F-11 verification gate.
/// </summary>
internal sealed class MockNwcRelay : IAsyncDisposable
{
    private readonly HttpListener _listener;
    private readonly ECPrivKey _walletPriv;
    private readonly string _walletPubkeyHex;
    private readonly string _preimageHex;
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;

    public string Url { get; }

    /// <summary>
    /// When set, the kind-23195 response EVENT is published under THIS subscription id
    /// instead of the one the client opened with its REQ. Lets a test prove the client
    /// ignores events delivered for a different subscription (msgArray[1] != subId).
    /// </summary>
    public string? SubIdOverride { get; set; }

    /// <summary>
    /// When true, the kind-23195 response carries syntactically INVALID JSON as its
    /// (correctly NIP-04 encrypted) content. The client decrypts it fine but the
    /// subsequent JsonDocument.Parse would throw — letting a test prove the client treats
    /// undecodable/invalid-JSON responses as "not for us" (continue) rather than letting a
    /// raw JsonException escape PayInvoiceAsync.
    /// </summary>
    public bool MalformedJsonPayload { get; set; }

    /// <summary>
    /// When set, a REQ for kind 13194 (the client's NIP-47 INFO-event auto-detect probe)
    /// is answered with a signed kind-13194 event whose <c>encryption</c> tag carries this
    /// value (e.g. <c>"nip04 nip44_v2"</c>), then EOSE. When null, the probe gets EOSE only
    /// (simulating an older wallet that never published a 13194 event → client falls back to
    /// NIP-04).
    /// </summary>
    public string? InfoEncryptionTag { get; set; }

    /// <summary>
    /// When true, the "wallet" only understands NIP-44 v2: a kind-23194 request encrypted
    /// with NIP-04 (has the <c>?iv=</c> marker) is silently ignored (no 23195 reply),
    /// modelling Alby Hub. A NIP-44 request is decrypted and answered normally. This is the
    /// exact condition under which a NIP-04-only client times out — the bug under test.
    /// </summary>
    public bool RequireNip44 { get; set; }

    public MockNwcRelay(ECPrivKey walletPriv, string walletPubkeyHex, string preimageHex)
    {
        _walletPriv = walletPriv;
        _walletPubkeyHex = walletPubkeyHex;
        _preimageHex = preimageHex;

        var port = GetFreePort();
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        Url = $"ws://127.0.0.1:{port}/";
    }

    public Task StartAsync()
    {
        _listener.Start();
        _acceptLoop = Task.Run(AcceptLoopAsync);
        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); }
                catch { break; }

                if (!ctx.Request.IsWebSocketRequest)
                {
                    ctx.Response.StatusCode = 400;
                    ctx.Response.Close();
                    continue;
                }

                var wsCtx = await ctx.AcceptWebSocketAsync(subProtocol: null);
                _ = Task.Run(() => HandleClientAsync(wsCtx.WebSocket));
            }
        }
        catch
        {
            // Listener disposed during shutdown — expected.
        }
    }

    private async Task HandleClientAsync(WebSocket ws)
    {
        var buffer = new byte[16384];
        var sb = new StringBuilder();
        string? subId = null;

        try
        {
            while (ws.State == WebSocketState.Open && !_cts.IsCancellationRequested)
            {
                var result = await ws.ReceiveAsync(buffer, _cts.Token);
                if (result.MessageType == WebSocketMessageType.Close) break;

                sb.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                if (!result.EndOfMessage) continue;

                var message = sb.ToString();
                sb.Clear();

                var arr = JsonNode.Parse(message)?.AsArray();
                if (arr == null || arr.Count < 2) continue;

                var type = arr[0]?.GetValue<string>();
                if (type == "REQ")
                {
                    var reqSubId = arr[1]?.GetValue<string>();
                    var filter = arr.Count > 2 ? arr[2]?.AsObject() : null;
                    var kinds = filter?["kinds"]?.AsArray();
                    var wantsInfo = kinds != null && kinds.Any(k => k?.GetValue<int>() == 13194);

                    if (wantsInfo)
                    {
                        // The client's NIP-47 INFO-event auto-detect probe (its own connection).
                        // Answer with a signed 13194 event when configured, then EOSE.
                        if (InfoEncryptionTag != null)
                        {
                            var infoEv = BuildSignedInfoEvent(InfoEncryptionTag);
                            var infoMsg = new JsonArray { "EVENT", reqSubId, JsonNode.Parse(infoEv.ToJsonString()) };
                            await SendAsync(ws, infoMsg.ToJsonString());
                        }
                        await SendAsync(ws, new JsonArray { "EOSE", reqSubId }.ToJsonString());
                    }
                    else
                    {
                        // The pay-response subscription (kind 23195). Remember its id for the reply.
                        subId = reqSubId;
                        await SendAsync(ws, new JsonArray { "EOSE", reqSubId }.ToJsonString());
                    }
                }
                else if (type == "EVENT" && arr.Count >= 2)
                {
                    var ev = arr[1]?.AsObject();
                    if (ev == null) continue;
                    if (ev["kind"]?.GetValue<int>() != 23194) continue;

                    var reqEventId = ev["id"]?.GetValue<string>() ?? "";
                    var clientPubHex = ev["pubkey"]?.GetValue<string>() ?? "";
                    var clientPubBytes = Convert.FromHexString(clientPubHex);
                    var encryptedReq = ev["content"]?.GetValue<string>() ?? "";

                    // Acknowledge the published event (relay-level OK — independent of whether
                    // the wallet can decrypt/process it).
                    await SendAsync(ws, new JsonArray { "OK", reqEventId, true, "" }.ToJsonString());

                    // NIP-04 requests carry the "?iv=" marker; NIP-44 v2 requests are a single
                    // base64 blob. A NIP-44-only wallet silently ignores a NIP-04 request.
                    var isNip44Request = !encryptedReq.Contains("?iv=");
                    if (RequireNip44 && !isNip44Request)
                        continue; // Alby-Hub-style: drop the undecryptable NIP-04 request, no reply.

                    // Try to decrypt the request to confirm it's a real pay_invoice.
                    // In the forged-relay test the relay's key is the ATTACKER's, which
                    // can't decrypt a request the client encrypted to the real wallet —
                    // we still reply so the (wrong-pubkey, validly-signed) response
                    // reaches and is rejected by the client's F-11 gate, rather than
                    // silently producing no reply.
                    try
                    {
                        var decryptedReq = NwcWallet.DecryptContent(encryptedReq, clientPubBytes, _walletPriv);
                        using var reqDoc = JsonDocument.Parse(decryptedReq);
                        var method = reqDoc.RootElement.GetProperty("method").GetString();
                        if (method != "pay_invoice") continue;
                    }
                    catch
                    {
                        // Decryption failed (forged-relay scenario) — reply anyway.
                    }

                    // Build the response payload and reply as a signed kind-23195 event.
                    // When MalformedJsonPayload is set, send content that decrypts cleanly
                    // but is NOT valid JSON, exercising the client's JsonException handling.
                    var responsePayload = MalformedJsonPayload
                        ? "this is not valid json {{{"
                        : new JsonObject
                        {
                            ["result_type"] = "pay_invoice",
                            ["result"] = new JsonObject { ["preimage"] = _preimageHex }
                        }.ToJsonString();

                    // Reply using the same scheme the client used for its request, so a
                    // NIP-44 request gets a NIP-44 reply (the client auto-detects inbound).
                    var encryptedResp = isNip44Request
                        ? NwcWallet.EncryptNip44(responsePayload, clientPubBytes, _walletPriv)
                        : NwcWallet.EncryptNip04(responsePayload, clientPubBytes, _walletPriv);

                    var createdAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    var tags = new JsonArray
                    {
                        new JsonArray { "p", clientPubHex },
                        new JsonArray { "e", reqEventId }
                    };
                    var respId = NwcWallet.ComputeEventId(_walletPubkeyHex, createdAt, 23195, tags, encryptedResp);
                    _walletPriv.TrySignBIP340(Convert.FromHexString(respId), null, out var sig);

                    var respEvent = new JsonObject
                    {
                        ["id"] = respId,
                        ["pubkey"] = _walletPubkeyHex,
                        ["created_at"] = createdAt,
                        ["kind"] = 23195,
                        ["tags"] = JsonNode.Parse(tags.ToJsonString()),
                        ["content"] = encryptedResp,
                        ["sig"] = Convert.ToHexString(sig!.ToBytes()).ToLowerInvariant()
                    };

                    var publishSubId = SubIdOverride ?? subId;
                    var outMsg = new JsonArray { "EVENT", publishSubId, JsonNode.Parse(respEvent.ToJsonString()) };
                    await SendAsync(ws, outMsg.ToJsonString());
                }
            }
        }
        catch
        {
            // Connection closed / cancelled during shutdown — expected.
        }
    }

    /// <summary>
    /// Builds a signed kind-13194 (NIP-47 INFO) event advertising the given encryption
    /// schemes, so the client's auto-detect probe verifies it and reads the tag.
    /// </summary>
    private JsonObject BuildSignedInfoEvent(string encryptionTag)
    {
        var createdAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var tags = new JsonArray { new JsonArray { "encryption", encryptionTag } };
        const string content = "Wallet capabilities: pay_invoice get_balance make_invoice";
        var id = NwcWallet.ComputeEventId(_walletPubkeyHex, createdAt, 13194, tags, content);
        _walletPriv.TrySignBIP340(Convert.FromHexString(id), null, out var sig);

        return new JsonObject
        {
            ["id"] = id,
            ["pubkey"] = _walletPubkeyHex,
            ["created_at"] = createdAt,
            ["kind"] = 13194,
            ["tags"] = JsonNode.Parse(tags.ToJsonString()),
            ["content"] = content,
            ["sig"] = Convert.ToHexString(sig!.ToBytes()).ToLowerInvariant()
        };
    }

    private static async Task SendAsync(WebSocket ws, string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        await ws.SendAsync(bytes, WebSocketMessageType.Text, true, CancellationToken.None);
    }

    private static int GetFreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        try { _listener.Stop(); _listener.Close(); } catch { }
        if (_acceptLoop != null)
        {
            try { await _acceptLoop; } catch { }
        }
        _cts.Dispose();
    }
}
