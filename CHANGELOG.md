# Changelog

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
