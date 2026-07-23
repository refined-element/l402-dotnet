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
    // Match the WHOLE human-readable part: ln + network + optional(amount +
    // multiplier). Terminated with "$" (not a trailing "1") so it only ever
    // matches a complete HRP, never a prefix that stops at an earlier "1". The
    // HRP is isolated first (HumanReadablePart); anchoring here as well means a
    // digit sitting in the bech32 data part can never be lifted out as the amount.
    private static readonly Regex Bolt11HrpPattern = new(
        @"^ln(?<network>[a-z]+?)(?<amount>\d+)?(?<multiplier>[munp])?$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Dictionary<char, decimal> Multipliers = new()
    {
        ['m'] = 0.001m,
        ['u'] = 0.000_001m,
        ['n'] = 0.000_000_001m,
        ['p'] = 0.000_000_000_001m,
    };

    private const decimal SatsPerBtc = 100_000_000m;

    // Why a decode did not yield a usable, strictly-positive sats amount. Shared
    // by ExtractAmountSats and ClassifyMissingAmount so the two never disagree on
    // the reason (e.g. a zero amount reported as "too large").
    private enum DecodeStatus { Ok, Unparseable, NoAmount, NonPositive, OutOfRange }

    /// <summary>
    /// The BOLT11 human-readable part — everything before the bech32 separator,
    /// which per BIP-173 is the LAST "1" (the data charset excludes "1", so every
    /// earlier "1" belongs to the HRP, only ever inside the amount). Isolating the
    /// HRP with LastIndexOf — rather than letting a regex stop at the FIRST "1" —
    /// is what stops a digit in the data part being read as the amount (#74).
    /// </summary>
    private static string? HumanReadablePart(string bolt11)
    {
        var invoice = bolt11.Trim().ToLowerInvariant();
        var separator = invoice.LastIndexOf('1');
        return separator < 0 ? null : invoice[..separator];
    }

    private static (DecodeStatus Status, int Sats) Decode(string bolt11)
    {
        if (string.IsNullOrWhiteSpace(bolt11))
            return (DecodeStatus.Unparseable, 0);

        var hrp = HumanReadablePart(bolt11);
        if (hrp is null)
            return (DecodeStatus.Unparseable, 0);

        var match = Bolt11HrpPattern.Match(hrp);
        if (!match.Success)
            return (DecodeStatus.Unparseable, 0);

        var amountGroup = match.Groups["amount"];
        if (!amountGroup.Success)
            return (DecodeStatus.NoAmount, 0); // "any amount" invoice

        try
        {
            var amount = decimal.Parse(amountGroup.Value);
            var multiplierGroup = match.Groups["multiplier"];
            var btcAmount = multiplierGroup.Success
                ? amount * Multipliers[char.ToLowerInvariant(multiplierGroup.Value[0])]
                : amount; // No multiplier means BTC

            var sats = btcAmount * SatsPerBtc;
            if (sats > int.MaxValue)
                return (DecodeStatus.OutOfRange, 0);

            var intSats = (int)sats;
            // A zero / sub-satoshi amount decodes to <= 0 sats: the invoice pins
            // no payable amount, so the wallet — not the server — would pick the
            // spend. Treat it as amountless (unknown), never a 0-sat blank cheque.
            return intSats > 0 ? (DecodeStatus.Ok, intSats) : (DecodeStatus.NonPositive, 0);
        }
        catch (OverflowException)
        {
            // Above int.MaxValue sats (~21.47 BTC) the total does not fit, and enough
            // digits overflow decimal.Parse before that. Either way the amount is one we
            // cannot state, which is the same position as an amountless invoice.
            return (DecodeStatus.OutOfRange, 0);
        }
    }

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
    public static MissingAmountReason ClassifyMissingAmount(string bolt11) => Decode(bolt11).Status switch
    {
        DecodeStatus.OutOfRange => MissingAmountReason.AmountOutOfRange,
        DecodeStatus.Unparseable => MissingAmountReason.Unparseable,
        // NoAmount (amountless) and NonPositive (zero / sub-satoshi) both mean the
        // invoice pins no payable amount — reported together as "no amount encoded"
        // so a zero invoice is never misdescribed as "too large".
        _ => MissingAmountReason.NoAmountEncoded,
    };

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
    /// Amount in satoshis (strictly positive), or null if it cannot be determined — none is
    /// encoded ("any amount" invoices), it is non-positive (a zero / sub-satoshi amount, which
    /// the payer would otherwise pick), the invoice cannot be parsed, or the amount is too large
    /// to represent. Use <see cref="ClassifyMissingAmount"/> to tell those apart.
    /// </returns>
    public static int? ExtractAmountSats(string bolt11)
    {
        var (status, sats) = Decode(bolt11);
        return status == DecodeStatus.Ok ? sats : null;
    }
}
