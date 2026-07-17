using System.Text.RegularExpressions;

namespace L402Requests;

/// <summary>
/// Why <see cref="Bolt11Invoice.ExtractAmountSats"/> could not determine an amount.
/// Both values mean the amount is unknown and so cannot be authorised, but they
/// point at different causes: a server that sent an amountless invoice, versus one
/// that sent something malformed or unsupported.
/// </summary>
public enum MissingAmountReason
{
    /// <summary>
    /// The invoice parsed fine but carries no amount — a zero-amount / "any amount"
    /// invoice, where the payer picks the value.
    /// </summary>
    NoAmountEncoded,

    /// <summary>The string could not be read as a BOLT11 invoice at all.</summary>
    Unparseable,

    /// <summary>
    /// An amount was encoded, but it is too large to represent in satoshis
    /// (above <see cref="int.MaxValue"/>, i.e. ~21.47 BTC).
    /// </summary>
    AmountOutOfRange,
}

/// <summary>
/// Pure C# BOLT11 invoice amount extraction.
/// Parses the human-readable part to extract the amount in satoshis.
/// No external Lightning libraries required.
/// </summary>
public static class Bolt11Invoice
{
    // Match: ln + network + optional(amount + optional multiplier) + "1" separator
    private static readonly Regex Bolt11Pattern = new(
        @"^ln(?<network>[a-z]+?)(?<amount>\d+)?(?<multiplier>[munp])?1",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Dictionary<char, decimal> Multipliers = new()
    {
        ['m'] = 0.001m,
        ['u'] = 0.000_001m,
        ['n'] = 0.000_000_001m,
        ['p'] = 0.000_000_000_001m,
    };

    private const decimal SatsPerBtc = 100_000_000m;

    /// <summary>
    /// Explain why <see cref="ExtractAmountSats"/> returned null for an invoice.
    /// </summary>
    /// <remarks>
    /// Only meaningful when <see cref="ExtractAmountSats"/> returned null; it re-reads
    /// the invoice to separate the two causes. Deliberately off the happy path — callers
    /// use it to build an error message, not to decide pay vs. refuse.
    /// </remarks>
    /// <param name="bolt11">The invoice <see cref="ExtractAmountSats"/> could not price.</param>
    /// <returns>Which of the two failure modes applies.</returns>
    public static MissingAmountReason ClassifyMissingAmount(string bolt11)
    {
        if (string.IsNullOrWhiteSpace(bolt11))
            return MissingAmountReason.Unparseable;

        var match = Bolt11Pattern.Match(bolt11.Trim().ToLowerInvariant());
        if (!match.Success)
            return MissingAmountReason.Unparseable;

        // The prefix read cleanly. With no amount group there was nothing to price;
        // with one, ExtractAmountSats only returns null when the value overflows, so
        // that is the remaining explanation. Deciding it from the match rather than
        // redoing the arithmetic keeps this in step with ExtractAmountSats.
        return match.Groups["amount"].Success
            ? MissingAmountReason.AmountOutOfRange
            : MissingAmountReason.NoAmountEncoded;
    }

    /// <summary>
    /// Extract the amount in satoshis from a BOLT11 invoice string.
    /// </summary>
    /// <remarks>
    /// Callers must NOT read null as "no limit applies": an amount that cannot be
    /// determined cannot be checked against a budget, so it must be refused rather
    /// than paid.
    /// </remarks>
    /// <param name="bolt11">A BOLT11-encoded Lightning invoice (e.g., "lnbc10u1p...").</param>
    /// <returns>
    /// Amount in satoshis, or null if the amount cannot be determined — none is encoded
    /// (zero-amount / "any amount" invoices), the invoice cannot be parsed, or the amount
    /// is too large to represent. Use <see cref="ClassifyMissingAmount"/> to tell those apart.
    /// </returns>
    public static int? ExtractAmountSats(string bolt11)
    {
        if (string.IsNullOrWhiteSpace(bolt11))
            return null;

        var invoice = bolt11.Trim().ToLowerInvariant();
        var match = Bolt11Pattern.Match(invoice);
        if (!match.Success)
            return null;

        var amountGroup = match.Groups["amount"];
        if (!amountGroup.Success)
            return null; // "any amount" invoice

        try
        {
            var amount = decimal.Parse(amountGroup.Value);
            var multiplierGroup = match.Groups["multiplier"];

            decimal btcAmount;
            if (multiplierGroup.Success)
            {
                var multiplierChar = char.ToLowerInvariant(multiplierGroup.Value[0]);
                btcAmount = amount * Multipliers[multiplierChar];
            }
            else
            {
                btcAmount = amount; // No multiplier means BTC
            }

            return (int)(btcAmount * SatsPerBtc);
        }
        catch (OverflowException)
        {
            // Above int.MaxValue sats (~21.47 BTC) the total does not fit, and enough
            // digits overflow decimal.Parse before that. Either way the amount is one we
            // cannot state, which is the same position as an amountless invoice: return
            // null so it takes the refusal path instead of throwing OverflowException out
            // of the caller's send, past every documented L402Exception.
            return null;
        }
    }
}
