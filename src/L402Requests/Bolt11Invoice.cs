using System.Text.RegularExpressions;

namespace L402Requests;

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
    /// Extract the amount in satoshis from a BOLT11 invoice string.
    /// </summary>
    /// <param name="bolt11">A BOLT11-encoded Lightning invoice (e.g., "lnbc10u1p...").</param>
    /// <returns>Amount in satoshis, or null if no amount is encoded (zero-amount / "any amount" invoices).</returns>
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
}
