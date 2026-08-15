using System.Net;
using FluentAssertions;
using L402Requests.Wallets;

namespace L402Requests.Tests;

/// <summary>
/// Funds-safety concurrency test for the budget enforcement path.
///
/// The bug: <see cref="BudgetController"/> was checked (Check) and recorded
/// (RecordPayment) as two separate steps around the wallet call, with the lock
/// released between them. Two concurrent payments could both pass the check
/// against the same pre-payment total and both settle, exceeding the cap — a
/// classic check-then-pay-then-record TOCTOU race.
///
/// The fix: an atomic reserve/commit/release lifecycle. TryReserve evaluates the
/// caps INCLUDING other in-flight reservations under one lock and records the
/// reservation, so two concurrent reservations cannot both pass.
/// </summary>
public class BudgetConcurrencyTests
{
    private const string TestMacaroon = "test_macaroon_concurrency";
    private const string TestInvoice = "lnbc10u1ptest"; // 1000 sats
    private const string TestPreimage =
        "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567";

    /// <summary>
    /// Thread-safe handler: 402 for the initial (unauthorized) request, 200 for the
    /// paid retry (which carries an Authorization header). No shared mutable queue —
    /// a fresh response per call — so it is safe under concurrency.
    /// </summary>
    private sealed class ConcurrentL402Handler : HttpMessageHandler
    {
        private int _paidResponses;
        public int PaidResponses => Volatile.Read(ref _paidResponses);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Contains("Authorization"))
            {
                Interlocked.Increment(ref _paidResponses);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("paid content"),
                });
            }

            var challenge = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
            challenge.Headers.WwwAuthenticate.ParseAdd(
                $"""L402 macaroon="{TestMacaroon}", invoice="{TestInvoice}" """);
            return Task.FromResult(challenge);
        }
    }

    /// <summary>
    /// Wallet that parks inside PayInvoiceAsync until the test opens the gate, so two
    /// concurrent payments are guaranteed to be in flight at the same time — the exact
    /// window the check-then-pay-then-record race needs to be observable.
    /// </summary>
    private sealed class GateControlledWallet : IWallet
    {
        private readonly ManualResetEventSlim _gate;
        private int _payAttempts;
        public int PayAttempts => Volatile.Read(ref _payAttempts);

        public GateControlledWallet(ManualResetEventSlim gate) => _gate = gate;

        public bool SupportsPreimage => true;
        public string Name => "GateControlled";

        public async Task<string> PayInvoiceAsync(string bolt11, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _payAttempts);
            // Park on a background thread so the caller genuinely blocks here (both
            // concurrent payments held open together) rather than completing inline.
            await Task.Run(() => _gate.Wait(ct), ct);
            return TestPreimage;
        }
    }

    [Fact]
    public async Task ConcurrentPayments_ExceedingHourlyCap_OnlyOneSettles()
    {
        using var gate = new ManualResetEventSlim(false);
        var handler = new ConcurrentL402Handler();
        var httpClient = new HttpClient(handler);
        var wallet = new GateControlledWallet(gate);

        // Each payment is 1000 sats. Per-request allows one; the hourly cap allows only
        // one. Two concurrent 1000-sat payments sum to 2000 > 1000 — exactly one must
        // settle.
        var budget = new BudgetController(
            maxSatsPerRequest: 1000,
            maxSatsPerHour: 1000,
            maxSatsPerDay: 1_000_000);
        var client = new L402HttpClient(httpClient, wallet, budget, new CredentialCache());

        // Distinct paths so each request has its own credential-cache key. Same-path
        // requests could let a late second request reuse the first's cached credential
        // and get a 200 without paying — legitimate cache reuse, but it would mask the
        // budget assertion. Distinct paths force both to actually attempt payment, so the
        // budget race is the only thing under test.
        var t1 = Task.Run(() => AttemptAsync(client, "https://example.com/resource-a"));
        var t2 = Task.Run(() => AttemptAsync(client, "https://example.com/resource-b"));

        // Give both requests time to clear the budget gate and park inside the wallet.
        // In the buggy check-then-pay-then-record design both pass the check (spent=0)
        // and park; in the fixed reserve-then-pay design only one reserves and the other
        // is denied before it ever reaches the wallet.
        await Task.Delay(300);

        gate.Set(); // release any parked payment(s)

        var results = await Task.WhenAll(t1, t2);

        var succeeded = results.Count(r => r.Ok);
        var denied = results.Count(r => r.Denied);

        // The core funds-safety invariant: total settled spend never exceeds the cap.
        budget.SpentLastHour().Should().BeLessOrEqualTo(1000,
            "concurrent payments must not both settle against the same pre-payment total");
        client.SpendingLog.TotalSpent().Should().BeLessOrEqualTo(1000);

        // Exactly one succeeds; exactly one is refused by the budget.
        succeeded.Should().Be(1);
        denied.Should().Be(1);
        handler.PaidResponses.Should().Be(1);
    }

    private sealed record Attempt(bool Ok, bool Denied);

    private static async Task<Attempt> AttemptAsync(L402HttpClient client, string url)
    {
        try
        {
            var resp = await client.GetAsync(url);
            return new Attempt(resp.StatusCode == HttpStatusCode.OK, false);
        }
        catch (BudgetExceededException)
        {
            return new Attempt(false, true);
        }
    }
}
