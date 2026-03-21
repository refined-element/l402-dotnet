using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace L402Requests;

/// <summary>
/// Common interface for payment challenges (L402 or MPP).
/// </summary>
public interface IPaymentChallenge
{
    string Invoice { get; }
}

/// <summary>
/// Parsed L402 challenge from a WWW-Authenticate header.
/// </summary>
public sealed record L402Challenge(string Macaroon, string Invoice) : IPaymentChallenge
{
    /// <summary>
    /// Parse a WWW-Authenticate header value containing an L402 challenge.
    /// Supports L402 and LSAT prefixes, quoted and unquoted values.
    /// </summary>
    public static L402Challenge Parse(string header)
    {
        if (string.IsNullOrWhiteSpace(header))
            throw new ChallengeParseException(header ?? "", "empty header");

        var match = QuotedPattern.Match(header);
        if (!match.Success)
            match = UnquotedPattern.Match(header);

        if (!match.Success)
            throw new ChallengeParseException(header, "no L402/LSAT challenge found");

        var macaroon = match.Groups["macaroon"].Value.Trim();
        var invoice = match.Groups["invoice"].Value.Trim();

        if (string.IsNullOrEmpty(macaroon))
            throw new ChallengeParseException(header, "empty macaroon");
        if (string.IsNullOrEmpty(invoice))
            throw new ChallengeParseException(header, "empty invoice");

        return new L402Challenge(macaroon, invoice);
    }

    /// <summary>
    /// Try to find an L402 challenge in the response headers.
    /// Returns null if no valid L402 challenge is found.
    /// </summary>
    public static L402Challenge? TryParse(HttpResponseMessage response)
    {
        if (response.Headers.WwwAuthenticate.Count == 0)
            return null;

        // Check each WWW-Authenticate header value
        foreach (var authHeader in response.Headers.WwwAuthenticate)
        {
            var headerValue = authHeader.ToString();
            try
            {
                return Parse(headerValue);
            }
            catch (ChallengeParseException)
            {
                continue;
            }
        }

        return null;
    }

    /// <summary>
    /// Tries to parse the best payment challenge from an HTTP response.
    /// Prefers L402 when available; falls back to MPP.
    /// </summary>
    public static IPaymentChallenge? TryParsePaymentChallenge(HttpResponseMessage response)
    {
        if (response.Headers.WwwAuthenticate.Count == 0)
            return null;

        IPaymentChallenge? l402 = null;
        IPaymentChallenge? mpp = null;

        foreach (var header in response.Headers.WwwAuthenticate)
        {
            var headerStr = header.ToString();

            if (l402 is null)
            {
                try
                {
                    l402 = Parse(headerStr);
                }
                catch (ChallengeParseException)
                {
                    // Not an L402 header
                }
            }

            mpp ??= MppChallenge.Parse(headerStr);
        }

        // Prefer L402
        return l402 ?? mpp;
    }

    // L402 macaroon="...", invoice="..."
    private static readonly Regex QuotedPattern = new(
        @"(?:L402|LSAT)\s+macaroon=""(?<macaroon>[^""]+)""\s*,\s*invoice=""(?<invoice>[^""]+)""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // L402 macaroon=..., invoice=...  (no quotes)
    private static readonly Regex UnquotedPattern = new(
        @"(?:L402|LSAT)\s+macaroon=(?<macaroon>[^\s,]+)\s*,?\s*invoice=(?<invoice>[^\s,]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
}

/// <summary>
/// Represents an MPP (Machine Payments Protocol) challenge parsed from a WWW-Authenticate header.
/// Per IETF draft-ryan-httpauth-payment. Simpler than L402 — invoice + preimage only, no macaroon.
/// </summary>
public sealed record MppChallenge : IPaymentChallenge
{
    public required string Invoice { get; init; }
    public string? Amount { get; init; }
    public string? Realm { get; init; }

    private static readonly Regex PaymentPattern = new(
        @"Payment\s+.*?method=""lightning"".*?invoice=""(?<invoice>[^""]+)""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Try to parse an MPP challenge from a WWW-Authenticate header value.
    /// Returns null if the header is not a valid MPP Payment challenge with method="lightning".
    /// </summary>
    public static MppChallenge? Parse(string? header)
    {
        if (string.IsNullOrWhiteSpace(header))
            return null;

        var match = PaymentPattern.Match(header);
        if (!match.Success)
            return null;

        var invoice = match.Groups["invoice"].Value;
        if (string.IsNullOrEmpty(invoice))
            return null;

        // Extract optional fields
        var amountMatch = Regex.Match(header, @"amount=""(?<amount>[^""]+)""", RegexOptions.IgnoreCase);
        var realmMatch = Regex.Match(header, @"realm=""(?<realm>[^""]+)""", RegexOptions.IgnoreCase);

        return new MppChallenge
        {
            Invoice = invoice,
            Amount = amountMatch.Success ? amountMatch.Groups["amount"].Value : null,
            Realm = realmMatch.Success ? realmMatch.Groups["realm"].Value : null
        };
    }
}
