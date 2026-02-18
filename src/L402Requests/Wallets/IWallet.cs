namespace L402Requests.Wallets;

/// <summary>
/// Interface for Lightning wallet adapters.
/// Implementations pay BOLT11 invoices and return the payment preimage.
/// </summary>
public interface IWallet
{
    /// <summary>
    /// Pay a BOLT11 invoice and return the preimage (hex).
    /// </summary>
    /// <param name="bolt11">BOLT11-encoded Lightning invoice string.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Payment preimage as a hex string.</returns>
    Task<string> PayInvoiceAsync(string bolt11, CancellationToken ct = default);

    /// <summary>
    /// Whether this wallet returns payment preimages (required for L402).
    /// </summary>
    bool SupportsPreimage { get; }

    /// <summary>
    /// Display name for this wallet adapter.
    /// </summary>
    string Name { get; }
}
