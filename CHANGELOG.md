# Changelog

## 0.9.0

**.NET 10 support.** The package now multi-targets `net8.0;net10.0`, adding a first-class `net10.0` (current LTS) target. The `net8.0` target is unchanged — same code, same dependency version floors (`Microsoft.Extensions.Http` 8.0.1, `Microsoft.Extensions.DependencyInjection.Abstractions` 8.0.2), so existing .NET 8 consumers see no behavioral or dependency change.

## 0.8.1

**Bug fix — NWC multi-relay wallets.** A Nostr Wallet Connect (NWC) connection string that advertises more than one relay (e.g. Alby Hub lists two `relay=` params for redundancy) was mishandled: the relay URLs were comma-joined into a single invalid URI (`wss://a,wss://b`), so `PayInvoiceAsync` threw a `UriFormatException` and no payment could be made. The client now:

- Parses **all** advertised `relay=` params and validates each is a well-formed `ws://`/`wss://` URI up front — a comma-joined or scheme-less value is rejected at construction with a clear message, not late at connect time.
- **Fails over across relays** at connect: it tries each advertised relay in order and only surfaces an error once every relay is unreachable. Single-relay behavior is byte-for-byte unchanged.

## 0.8.0

**Funds-safety — atomic budget reservations.** Closed a check-then-pay TOCTOU race in the budget controller: two concurrent payments could each pass the spend check against the same remaining balance and then both pay, together exceeding the configured cap. Spending is now reserved atomically before the wallet call and committed (idempotently) or released afterward, so concurrent invocations can never collectively overspend the budget.

## 0.7.1

**Security fix — upgrade recommended.** Completes 0.7.0's "refuse an invoice whose amount can't be positively bounded" guarantee by closing two remaining ways an unbounded or ambiguous invoice could still be paid:

- **Literal-zero invoices.** A BOLT11 invoice encoding a literal `0` amount (e.g. `lnbc0p1...`) decoded to `0`, which slipped past the "no amount" check, passed the budget check, and reached the wallet as an effectively-amountless invoice (the wallet then chooses the actual spend). The resolved amount must now be **strictly positive from every source** (BOLT11 decode and MPP fallback); `0` or negative is refused.
- **Decoder amount injection (HRP-anchoring).** The amount regex was terminated by the first `1`, so a crafted invoice could smuggle digits from the bech32 data part and decode to a bogus positive that passed the budget check with a fabricated number. The amount is now read **only from the human-readable part** (isolated at the true last-`1` separator), so data-part digits can't influence it.

## 0.7.0

**Security fix — upgrade recommended.** An invoice whose amount could not be read was treated as "no amount to check" and paid anyway, skipping `BudgetController.Check` altogether. That went well beyond the sats limits:

- **The domain allowlist was bypassed.** `AllowedDomains` is enforced inside the same `Check` call the missing amount skipped, so an amountless invoice was paid from *any* domain, allowlisted or not.
- **The spend was never recorded.** It never reached the `SpendingLog`, so it stayed out of every later budget check and out of any audit of what the client had already spent.

A server that wanted a blank cheque only had to send an invoice with no amount.

**Breaking:** invoices with no readable amount now throw `InvoiceAmountUnknownException` instead of being paid.

**Breaking:** wallets that cannot return a preimage (OpenNode) now throw `UnsupportedWalletException` *before* paying. Previously the withdrawal was submitted first and only then failed with `PaymentFailedException` — you paid and got nothing. `UnsupportedWalletException` is not a `PaymentFailedException` subclass, so `catch (PaymentFailedException)` blocks that used to catch this will now let it escape. OpenNode is still auto-detected, so an `OPENNODE_API_KEY`-only setup now refuses every 402.

Also fixed: invoice amounts above ~21.47 BTC (`int.MaxValue` sats) no longer throw a raw `OverflowException` out of `SendAsync`. They are refused like any other unreadable amount, as `InvoiceAmountUnknownException` with the new `MissingAmountReason.AmountOutOfRange`.

Both refusals apply to `L402HttpClient` and `L402DelegatingHandler`.
