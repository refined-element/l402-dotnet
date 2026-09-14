using System.Security.Cryptography;

namespace L402Requests.Wallets;

/// <summary>What a wallet established about an outgoing payment when asked by payment hash.</summary>
public enum PaymentLookupStatus
{
    /// <summary>The wallet reports a settled (SUCCEEDED) outgoing payment for exactly this hash.</summary>
    Paid,

    /// <summary>The wallet definitively reports no successful payment for this hash (never attempted, or failed).</summary>
    NotPaid,

    /// <summary>
    /// Nothing can be concluded: transport/auth error, unparseable reply, an in-flight payment, a
    /// preimage that does not open the hash, or a wallet that cannot look payments up by hash at all.
    /// </summary>
    Unknown,
}

/// <summary>
/// Result of <see cref="IPaymentLookup.LookupPaymentAsync"/>. <see cref="PreimageHex"/> is only set on
/// <see cref="PaymentLookupStatus.Paid"/> and has been verified (<c>SHA-256(preimage) == hash</c>) by the
/// adapter before it is returned. Callers MUST NOT log it.
/// </summary>
public sealed record PaymentLookupResult(PaymentLookupStatus Status, string? PreimageHex = null, long? AmountSats = null)
{
    public static readonly PaymentLookupResult Unknown = new(PaymentLookupStatus.Unknown);
    public static readonly PaymentLookupResult NotPaid = new(PaymentLookupStatus.NotPaid);

    public static PaymentLookupResult Paid(string? preimageHex, long? amountSats)
        => new(PaymentLookupStatus.Paid, preimageHex, amountSats);
}

/// <summary>
/// Optional wallet capability: look up an OUTGOING Lightning payment by its BOLT11 payment hash, so a
/// caller whose <see cref="IWallet.PayInvoiceAsync"/> call ended ambiguously (timeout, network cut,
/// process crash) can reconcile what actually happened to the money.
/// <para/>
/// CONTRACT:
/// <list type="bullet">
///   <item>NEVER throws for transport, auth, timeout or parse errors — those answer <see cref="PaymentLookupStatus.Unknown"/>.</item>
///   <item><see cref="PaymentLookupStatus.Paid"/> only when the wallet reports a settled outgoing payment for
///   that exact hash; when the reply carries a preimage it must hash to the requested payment hash, otherwise
///   the answer is <see cref="PaymentLookupStatus.Unknown"/> (a wrong preimage is not proof).</item>
///   <item><see cref="PaymentLookupStatus.NotPaid"/> only for a definitive not-found / failed verdict.</item>
///   <item><paramref name="paymentHash"/> must be 64 lowercase hex characters; anything else is rejected with
///   <see cref="ArgumentException"/> BEFORE any network call (that is a caller bug, not a wallet outcome).</item>
/// </list>
/// </summary>
public interface IPaymentLookup
{
    Task<PaymentLookupResult> LookupPaymentAsync(string paymentHash, CancellationToken ct = default);
}

/// <summary>Shared validation for <see cref="IPaymentLookup"/> implementations.</summary>
public static class PaymentLookupSupport
{
    /// <summary>True when <paramref name="paymentHash"/> is exactly 64 lowercase hex characters.</summary>
    public static bool IsValidPaymentHash(string? paymentHash)
    {
        if (paymentHash is null || paymentHash.Length != 64) return false;
        foreach (var c in paymentHash)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    /// <summary>Throws <see cref="ArgumentException"/> unless <paramref name="paymentHash"/> is 64 lowercase hex characters.</summary>
    public static void EnsureValidPaymentHash(string? paymentHash, string paramName = "paymentHash")
    {
        if (!IsValidPaymentHash(paymentHash))
            throw new ArgumentException("paymentHash must be exactly 64 lowercase hex characters.", paramName);
    }

    /// <summary>
    /// True when <paramref name="preimageHex"/> is 32 bytes of hex (any case) and SHA-256 of those bytes equals
    /// <paramref name="paymentHash"/>. Constant-time compare on the digest.
    /// </summary>
    public static bool PreimageOpensHash(string? preimageHex, string paymentHash)
    {
        if (string.IsNullOrEmpty(preimageHex) || preimageHex.Length != 64) return false;
        byte[] preimage;
        try { preimage = Convert.FromHexString(preimageHex); }
        catch (FormatException) { return false; }
        byte[] expected;
        try { expected = Convert.FromHexString(paymentHash); }
        catch (FormatException) { return false; }
        var actual = SHA256.HashData(preimage);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
