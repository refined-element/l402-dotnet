namespace L402Requests;

/// <summary>
/// Base64url (RFC 4648 §5) helpers shared by the modern draft-00 Payment
/// challenge/credential and the Payment-Receipt parser.
/// </summary>
internal static class Base64Url
{
    /// <summary>Encode bytes as base64url without padding.</summary>
    public static string Encode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Decode a base64url string, tolerating both padded and unpadded input
    /// (and the standard base64 alphabet). Returns null instead of throwing.
    /// </summary>
    public static byte[]? TryDecode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var s = value.Trim().Replace('-', '+').Replace('_', '/');
        var remainder = s.Length % 4;
        if (remainder == 1)
            return null; // never a valid base64 length
        if (remainder != 0)
            s += new string('=', 4 - remainder);

        try
        {
            return Convert.FromBase64String(s);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
