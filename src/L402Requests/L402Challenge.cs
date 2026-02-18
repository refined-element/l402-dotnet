using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace L402Requests;

/// <summary>
/// Parsed L402 challenge from a WWW-Authenticate header.
/// </summary>
public sealed record L402Challenge(string Macaroon, string Invoice)
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

    // L402 macaroon="...", invoice="..."
    private static readonly Regex QuotedPattern = new(
        @"(?:L402|LSAT)\s+macaroon=""(?<macaroon>[^""]+)""\s*,\s*invoice=""(?<invoice>[^""]+)""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // L402 macaroon=..., invoice=...  (no quotes)
    private static readonly Regex UnquotedPattern = new(
        @"(?:L402|LSAT)\s+macaroon=(?<macaroon>[^\s,]+)\s*,?\s*invoice=(?<invoice>[^\s,]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
}
