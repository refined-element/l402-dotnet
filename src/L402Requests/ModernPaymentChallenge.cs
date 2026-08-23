using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace L402Requests;

/// <summary>
/// A modern draft-00 Payment challenge (draft-httpauth-payment-00 +
/// draft-lightning-charge-00), parsed from a WWW-Authenticate header:
/// <c>Payment id="...", realm="...", method="lightning", intent="charge",
/// request="&lt;base64url(JSON)&gt;", expires="..."</c>.
/// </summary>
/// <remarks>
/// The discriminator between the modern and legacy Payment profiles is the
/// <c>request</c> param: present and non-empty means modern; a bare
/// <c>invoice=</c> param means the legacy profile (<see cref="MppChallenge"/>).
/// A server may send a superset header carrying both — the legacy
/// <c>invoice</c>/<c>amount</c>/<c>currency</c> params are unknown params here
/// and are ignored (and never echoed into the credential).
/// <para>
/// Credentials built from a modern challenge are SINGLE-USE server-side:
/// they must never be cached or replayed the way L402 tokens are.
/// </para>
/// </remarks>
public sealed record ModernPaymentChallenge : IPaymentChallenge
{
    /// <summary>Lightning invoice decoded from the request payload.</summary>
    public required string Invoice { get; init; }

    /// <summary>The method param — always "lightning" for a parsed challenge.</summary>
    public required string Method { get; init; }

    /// <summary>The intent param — always "charge" for a parsed challenge.</summary>
    public required string Intent { get; init; }

    /// <summary>
    /// The encoded request param exactly as received — echoed byte-exact into
    /// the credential, never decoded and re-encoded.
    /// </summary>
    public required string Request { get; init; }

    /// <summary>Challenge id, echoed into the credential when present.</summary>
    public string? Id { get; init; }

    /// <summary>Realm, echoed into the credential when present.</summary>
    public string? Realm { get; init; }

    /// <summary>RFC3339 expiry as received, echoed byte-exact when present.</summary>
    public string? Expires { get; init; }

    /// <summary>Optional digest param, echoed when present.</summary>
    public string? Digest { get; init; }

    /// <summary>Optional description param, echoed when present.</summary>
    public string? Description { get; init; }

    /// <summary>Optional opaque param, echoed when present.</summary>
    public string? Opaque { get; init; }

    /// <summary>Amount from the decoded request — a decimal string in satoshis.</summary>
    public string? Amount { get; init; }

    /// <summary>Currency from the decoded request ("sat" when present).</summary>
    public string? Currency { get; init; }

    /// <summary>Payment hash from the decoded request, when present.</summary>
    public string? PaymentHash { get; init; }

    /// <summary>Network from the decoded request (mainnet/regtest/signet), when present.</summary>
    public string? Network { get; init; }

    /// <summary>Parsed <see cref="Expires"/>, when it parsed as RFC3339.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>True when the challenge's expiry is already past. Do not pay an expired challenge.</summary>
    public bool IsExpired => ExpiresAt.HasValue && DateTimeOffset.UtcNow >= ExpiresAt.Value;

    private static readonly Regex SchemePattern = new(
        @"^Payment\s+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly JsonSerializerOptions CredentialJsonOptions = new()
    {
        // Compact JSON; relaxed escaping keeps RFC3339 offsets ("+02:00") and
        // similar header-param values readable. Values only ever land in an
        // Authorization header, not an HTML context.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Try to parse a modern draft-00 Payment challenge from a WWW-Authenticate
    /// header value. Returns null when the header is not a Payment challenge,
    /// has no non-empty request param (legacy profile), is malformed (bad
    /// base64url / bad JSON / missing invoice), or fails the client-side sanity
    /// checks (method must be "lightning", intent "charge", currency "sat" when
    /// present). Unknown params are ignored per RFC 9110.
    /// </summary>
    public static ModernPaymentChallenge? Parse(string? header)
    {
        if (string.IsNullOrWhiteSpace(header))
            return null;

        // The header must start with the "Payment" scheme
        if (!SchemePattern.IsMatch(header))
            return null;

        var paramStr = SchemePattern.Replace(header, "", 1);
        var parameters = ParseAuthParams(paramStr);

        // The request param is the modern-profile discriminator.
        if (!parameters.TryGetValue("request", out var request) || string.IsNullOrEmpty(request))
            return null;

        // Sanity checks before any payment is considered.
        if (!parameters.TryGetValue("method", out var method)
            || !string.Equals(method, "lightning", StringComparison.OrdinalIgnoreCase))
            return null;
        if (!parameters.TryGetValue("intent", out var intent)
            || !string.Equals(intent, "charge", StringComparison.OrdinalIgnoreCase))
            return null;

        var decoded = Base64Url.TryDecode(request);
        if (decoded is null)
            return null;

        string? amount, currency, invoice, paymentHash, network;
        try
        {
            using var doc = JsonDocument.Parse(decoded);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return null;

            amount = ReadString(doc.RootElement, "amount");
            currency = ReadString(doc.RootElement, "currency");

            if (!doc.RootElement.TryGetProperty("methodDetails", out var details)
                || details.ValueKind != JsonValueKind.Object)
                return null;

            invoice = ReadString(details, "invoice");
            paymentHash = ReadString(details, "paymentHash");
            network = ReadString(details, "network");
        }
        catch (JsonException)
        {
            return null;
        }

        if (string.IsNullOrEmpty(invoice))
            return null;

        // currency, when present, must be "sat" — anything else we cannot pay.
        if (currency is not null && !string.Equals(currency, "sat", StringComparison.OrdinalIgnoreCase))
            return null;

        parameters.TryGetValue("expires", out var expires);
        DateTimeOffset? expiresAt = null;
        if (expires is not null
            && DateTimeOffset.TryParse(expires, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsedExpires))
            expiresAt = parsedExpires;

        return new ModernPaymentChallenge
        {
            Invoice = invoice,
            Method = method,
            Intent = intent,
            Request = request,
            Id = parameters.TryGetValue("id", out var id) ? id : null,
            Realm = parameters.TryGetValue("realm", out var realm) ? realm : null,
            Expires = expires,
            Digest = parameters.TryGetValue("digest", out var digest) ? digest : null,
            Description = parameters.TryGetValue("description", out var description) ? description : null,
            Opaque = parameters.TryGetValue("opaque", out var opaque) ? opaque : null,
            Amount = amount,
            Currency = currency,
            PaymentHash = paymentHash,
            Network = network,
            ExpiresAt = expiresAt,
        };
    }

    /// <summary>
    /// Build the modern credential for the retry request:
    /// <c>Payment &lt;base64url(JSON, no padding)&gt;</c> where the JSON echoes
    /// every spec-defined challenge param exactly as received plus
    /// <c>payload.preimage</c> (lowercase hex). Single-use server-side — never
    /// cache the result.
    /// </summary>
    public string BuildAuthorizationHeader(string preimage)
    {
        var challenge = new JsonObject();
        if (Id is not null) challenge["id"] = Id;
        if (Realm is not null) challenge["realm"] = Realm;
        challenge["method"] = Method;
        challenge["intent"] = Intent;
        challenge["request"] = Request; // the received encoded string, byte-exact
        if (Expires is not null) challenge["expires"] = Expires;
        if (Digest is not null) challenge["digest"] = Digest;
        if (Description is not null) challenge["description"] = Description;
        if (Opaque is not null) challenge["opaque"] = Opaque;

        var credential = new JsonObject
        {
            ["challenge"] = challenge,
            ["payload"] = new JsonObject
            {
                // Wallets sometimes return uppercase hex; the wire format is lowercase.
                ["preimage"] = preimage.Trim().ToLowerInvariant(),
            },
        };

        var json = credential.ToJsonString(CredentialJsonOptions);
        return "Payment " + Base64Url.Encode(Encoding.UTF8.GetBytes(json));
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

    /// <summary>
    /// Tokenize RFC 9110 auth-params: comma/space separated <c>name=value</c>
    /// pairs where value is a token or a quoted-string (with backslash
    /// escapes — so quoted values may contain commas). Order-independent,
    /// case-insensitive names, first occurrence wins, unknown names kept so the
    /// caller can ignore them explicitly.
    /// </summary>
    private static Dictionary<string, string> ParseAuthParams(string paramStr)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var i = 0;
        while (i < paramStr.Length)
        {
            // Skip separators between params
            while (i < paramStr.Length && (paramStr[i] == ',' || char.IsWhiteSpace(paramStr[i])))
                i++;
            if (i >= paramStr.Length)
                break;

            // Read the param name up to '='
            var nameStart = i;
            while (i < paramStr.Length && paramStr[i] != '=' && paramStr[i] != ',' && !char.IsWhiteSpace(paramStr[i]))
                i++;
            if (i >= paramStr.Length || paramStr[i] != '=')
                continue; // bare token (no value) — skip it
            var name = paramStr[nameStart..i];
            i++; // skip '='

            string value;
            if (i < paramStr.Length && paramStr[i] == '"')
            {
                // quoted-string, honoring quoted-pair escapes
                i++;
                var sb = new StringBuilder();
                while (i < paramStr.Length && paramStr[i] != '"')
                {
                    if (paramStr[i] == '\\' && i + 1 < paramStr.Length)
                    {
                        sb.Append(paramStr[i + 1]);
                        i += 2;
                    }
                    else
                    {
                        sb.Append(paramStr[i]);
                        i++;
                    }
                }
                if (i < paramStr.Length)
                    i++; // closing quote
                value = sb.ToString();
            }
            else
            {
                var valueStart = i;
                while (i < paramStr.Length && paramStr[i] != ',' && !char.IsWhiteSpace(paramStr[i]))
                    i++;
                value = paramStr[valueStart..i];
            }

            if (name.Length > 0 && !result.ContainsKey(name))
                result[name] = value;
        }

        return result;
    }
}
