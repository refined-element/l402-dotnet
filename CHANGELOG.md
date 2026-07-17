# Changelog

## 0.7.0

- Fixes budget limits being skipped for invoices with no parseable amount — upgrade recommended. Such invoices are now refused with `InvoiceAmountUnknownException` instead of paid, and wallets that can't produce a preimage (OpenNode) are rejected with `UnsupportedWalletException` before paying rather than after. Both fixes apply to `L402HttpClient` and `L402DelegatingHandler`.
