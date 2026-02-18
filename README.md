# L402-Requests (.NET)

Auto-paying L402 HTTP client for .NET. APIs behind Lightning paywalls just work.

`L402Requests` wraps `HttpClient` and automatically handles HTTP 402 responses by paying Lightning invoices and retrying with L402 credentials. It's a drop-in HTTP client where any API behind an L402 paywall "just works."

## Install

```bash
dotnet add package L402Requests
```

## Quick Start

```csharp
using L402Requests;

using var client = new L402HttpClient();
var response = await client.GetAsync("https://api.example.com/paid-resource");
Console.WriteLine(await response.Content.ReadAsStringAsync());
```

That's it. The library detects your wallet from environment variables, pays the Lightning invoice when it gets a 402 response, and retries with L402 credentials.

## Wallet Configuration

Set environment variables for your preferred wallet. The library auto-detects in this order:

| Priority | Wallet | Environment Variables | Preimage Support |
|----------|--------|-----------------------|------------------|
| 1 | LND | `LND_REST_HOST`, `LND_MACAROON_HEX` | Yes |
| 2 | NWC | `NWC_CONNECTION_STRING` | Yes (CoinOS, CLINK) |
| 3 | Strike | `STRIKE_API_KEY` | Yes |
| 4 | OpenNode | `OPENNODE_API_KEY` | Limited |

**Recommended:** Strike (0% fee, full preimage support, no infrastructure required).

### Strike (Recommended)

```bash
export STRIKE_API_KEY="your-strike-api-key"
```

### LND

```bash
export LND_REST_HOST="https://localhost:8080"
export LND_MACAROON_HEX="your-admin-macaroon-hex"
export LND_TLS_CERT_PATH="/path/to/tls.cert"  # optional
```

### NWC (Nostr Wallet Connect)

```bash
export NWC_CONNECTION_STRING="nostr+walletconnect://pubkey?relay=wss://relay&secret=hex"
```

### OpenNode

```bash
export OPENNODE_API_KEY="your-opennode-key"
```

> **Note:** OpenNode does not return payment preimages, which limits L402 functionality. For full L402 support, use Strike, LND, or a compatible NWC wallet.

## Budget Controls

Safety first — budgets are enabled by default to prevent accidental overspending:

```csharp
using var client = new L402HttpClient(new L402Options
{
    MaxSatsPerRequest = 500,     // Max per single payment (default: 1000)
    MaxSatsPerHour = 5000,       // Hourly rolling limit (default: 10000)
    MaxSatsPerDay = 25000,       // Daily rolling limit (default: 50000)
    AllowedDomains = ["api.example.com"],  // Optional domain allowlist
});
```

If a payment would exceed any limit, `BudgetExceededException` is raised *before* the payment is attempted.

To disable budgets entirely:

```csharp
using var client = new L402HttpClient(new L402Options { BudgetEnabled = false });
```

## Explicit Wallet

```csharp
using L402Requests;
using L402Requests.Wallets;

using var client = new L402HttpClient(new StrikeWallet("your-api-key"));
var response = await client.GetAsync("https://api.example.com/paid-resource");
```

## DI / HttpClientFactory

```csharp
// In Program.cs
builder.Services.AddL402HttpClient("myapi", options =>
{
    options.MaxSatsPerRequest = 500;
    options.MaxSatsPerHour = 5000;
    options.AllowedDomains = ["api.example.com"];
});

// In consuming class
public class MyService(IHttpClientFactory factory)
{
    public async Task<string> GetPaidData()
    {
        var client = factory.CreateClient("myapi");
        var response = await client.GetAsync("https://api.example.com/paid-resource");
        return await response.Content.ReadAsStringAsync();
    }
}
```

## Spending Introspection

Track every payment made during a session:

```csharp
using var client = new L402HttpClient();
await client.GetAsync("https://api.example.com/data");
await client.GetAsync("https://api.example.com/more-data");

Console.WriteLine($"Total: {client.SpendingLog.TotalSpent()} sats");
Console.WriteLine($"Last hour: {client.SpendingLog.SpentLastHour()} sats");
Console.WriteLine($"By domain: {string.Join(", ", client.SpendingLog.ByDomain())}");
Console.WriteLine(client.SpendingLog.ToJson());
```

## How It Works

1. Your code makes an HTTP request via `L402HttpClient`
2. If the server returns **200**, the response is returned as-is
3. If the server returns **402** with an L402 challenge:
   - The `WWW-Authenticate: L402 macaroon="...", invoice="..."` header is parsed
   - The BOLT11 invoice amount is checked against your budget
   - The invoice is paid via your configured Lightning wallet
   - The request is retried with `Authorization: L402 {macaroon}:{preimage}`
4. Credentials are cached so subsequent requests to the same endpoint don't require re-payment

## Error Handling

```csharp
using L402Requests;

using var client = new L402HttpClient();
try
{
    var response = await client.GetAsync("https://api.example.com/paid-resource");
}
catch (BudgetExceededException e)
{
    Console.WriteLine($"Over budget: {e.LimitType} limit is {e.LimitSats} sats");
}
catch (PaymentFailedException e)
{
    Console.WriteLine($"Payment failed: {e.Reason}");
}
catch (NoWalletException)
{
    Console.WriteLine("No wallet configured");
}
```

| Exception | When |
|-----------|------|
| `BudgetExceededException` | Payment would exceed a budget limit |
| `PaymentFailedException` | Lightning payment failed |
| `InvoiceExpiredException` | Invoice expired before payment |
| `NoWalletException` | No wallet env vars detected |
| `DomainNotAllowedException` | Domain not in `AllowedDomains` |
| `ChallengeParseException` | Malformed L402 challenge header |

## What is L402?

L402 (formerly LSAT) is a protocol for monetizing APIs with Lightning Network micropayments. Instead of API keys or subscriptions, servers return HTTP 402 ("Payment Required") with a Lightning invoice. Once paid, the client receives a credential (macaroon + payment preimage) that grants access.

Learn more: [docs.lightningenable.com](https://docs.lightningenable.com)

## License

MIT — see [LICENSE](LICENSE).
