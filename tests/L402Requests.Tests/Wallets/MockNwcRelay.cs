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
                    subId = arr[1]?.GetValue<string>();
                    // Acknowledge end of stored events so the client moves to live mode.
                    var eose = new JsonArray { "EOSE", subId };
                    await SendAsync(ws, eose.ToJsonString());
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

                    // Acknowledge the published event.
                    await SendAsync(ws, new JsonArray { "OK", reqEventId, true, "" }.ToJsonString());

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

                    // Encrypt for the client using the wallet privkey + client pubkey (NIP-04).
                    var encryptedResp = NwcWallet.EncryptNip04(responsePayload, clientPubBytes, _walletPriv);

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
