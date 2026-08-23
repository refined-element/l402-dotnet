using System.Text.Json;

namespace L402Requests;

/// <summary>
/// A parsed <c>Payment-Receipt</c> response header (draft-00):
/// <c>base64url({"challengeId","method","reference","status","timestamp"})</c>
/// where <c>reference</c> is the payment hash. The receipt carries no secrets
/// (no preimage), so it is safe to store and log.
/// </summary>
/// <remarks>
/// Parsing is tolerant by design: the header is optional (older servers never
/// send it) and a malformed receipt must not fail an otherwise-successful
/// payment — <see cref="TryParse"/> returns null instead of throwing.
/// </remarks>
public sealed record PaymentReceipt(
    string? ChallengeId,
    string? Method,
    string? Reference,
    string? Status,
    string? Timestamp)
{
    /// <summary>
    /// Try to parse the Payment-Receipt header from a response. Returns null
    /// when the header is absent or malformed (bad base64url, bad JSON).
    /// Accepts base64url with or without padding.
    /// </summary>
    public static PaymentReceipt? TryParse(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Payment-Receipt", out var values))
            return null;

        var decoded = Base64Url.TryDecode(values.FirstOrDefault());
        if (decoded is null)
            return null;

        try
        {
            using var doc = JsonDocument.Parse(decoded);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return null;

            return new PaymentReceipt(
                ReadString(doc.RootElement, "challengeId"),
                ReadString(doc.RootElement, "method"),
                ReadString(doc.RootElement, "reference"),
                ReadString(doc.RootElement, "status"),
                ReadString(doc.RootElement, "timestamp"));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? ReadString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property))
            return null;
        return property.ValueKind switch
        {
            JsonValueKind.String => property.GetString(),
            JsonValueKind.Number => property.GetRawText(),
            _ => null,
        };
    }
}
