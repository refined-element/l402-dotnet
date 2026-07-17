namespace L402Requests;

/// <summary>
/// Base exception for L402-Requests.
/// </summary>
public class L402Exception : Exception
{
    public L402Exception(string message) : base(message) { }
    public L402Exception(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Payment would exceed configured budget limits.
/// Raised <em>before</em> the payment is attempted.
/// </summary>
public class BudgetExceededException : L402Exception
{
    public string LimitType { get; }
    public int LimitSats { get; }
    public int CurrentSats { get; }
    public int InvoiceSats { get; }

    public BudgetExceededException(string limitType, int limitSats, int currentSats, int invoiceSats)
        : base($"Budget exceeded: {limitType} limit is {limitSats} sats, already spent {currentSats} sats, invoice requires {invoiceSats} sats")
    {
        LimitType = limitType;
        LimitSats = limitSats;
        CurrentSats = currentSats;
        InvoiceSats = invoiceSats;
    }
}

/// <summary>
/// Lightning payment failed.
/// </summary>
public class PaymentFailedException : L402Exception
{
    public string Reason { get; }
    public string? Bolt11 { get; }

    public PaymentFailedException(string reason, string? bolt11 = null)
        : base($"Payment failed: {reason}")
    {
        Reason = reason;
        Bolt11 = bolt11;
    }
}

/// <summary>
/// Lightning invoice has expired.
/// </summary>
public class InvoiceExpiredException : L402Exception
{
    public string? Bolt11 { get; }

    public InvoiceExpiredException(string? bolt11 = null)
        : base("Invoice has expired")
    {
        Bolt11 = bolt11;
    }
}

/// <summary>
/// Failed to parse L402 challenge from WWW-Authenticate header.
/// </summary>
public class ChallengeParseException : L402Exception
{
    public string Header { get; }
    public string Reason { get; }

    public ChallengeParseException(string header, string reason)
        : base($"Failed to parse L402 challenge: {reason}")
    {
        Header = header;
        Reason = reason;
    }
}

/// <summary>
/// No wallet configured or auto-detected.
/// </summary>
public class NoWalletException : L402Exception
{
    public NoWalletException()
        : base("No wallet configured. Set environment variables for one of: " +
               "STRIKE_API_KEY, OPENNODE_API_KEY, NWC_CONNECTION_STRING, " +
               "LND_REST_HOST + LND_MACAROON_HEX")
    {
    }
}

/// <summary>
/// Domain is not in the allowed domains list.
/// </summary>
public class DomainNotAllowedException : L402Exception
{
    public string Domain { get; }

    public DomainNotAllowedException(string domain)
        : base($"Domain not in allowed list: {domain}")
    {
        Domain = domain;
    }
}

/// <summary>
/// The invoice amount could not be determined, so payment was refused.
/// Raised <em>before</em> the payment is attempted.
/// </summary>
/// <remarks>
/// An amount we cannot read is an amount we cannot check against the budget limits or
/// the domain allowlist, and one that would never reach the spending log — so paying it
/// would spend an unknown sum with every control silently skipped. No funds are spent.
/// Like <see cref="UnsupportedWalletException"/> this is a precondition failure rather
/// than a payment failure: code catching <see cref="PaymentFailedException"/> to retry
/// or log payment problems should not expect it.
/// </remarks>
public class InvoiceAmountUnknownException : L402Exception
{
    /// <summary>Why the amount could not be determined.</summary>
    public MissingAmountReason Reason { get; }

    /// <summary>The offending invoice, when available.</summary>
    public string? Bolt11 { get; }

    public InvoiceAmountUnknownException(MissingAmountReason reason, string? bolt11 = null)
        : base($"Refusing to pay: {Describe(reason)}, so its amount cannot be checked " +
               "against your budget. Only invoices with an explicit, readable amount are supported.")
    {
        Reason = reason;
        Bolt11 = bolt11;
    }

    private static string Describe(MissingAmountReason reason) => reason switch
    {
        MissingAmountReason.NoAmountEncoded => "the invoice encodes no amount",
        MissingAmountReason.Unparseable => "the invoice could not be parsed as BOLT11",
        MissingAmountReason.AmountOutOfRange => "the invoice amount is too large to represent in satoshis",
        _ => "the invoice amount could not be determined",
    };
}

/// <summary>
/// The configured wallet cannot fulfill L402's preimage requirement.
/// Raised <em>before</em> the payment is attempted.
/// </summary>
/// <remarks>
/// Thrown when the wallet's <see cref="Wallets.IWallet.SupportsPreimage"/> is false
/// (e.g. OpenNode). L402 needs the preimage to build the Authorization header, so paying
/// would spend funds for no access. This is a configuration failure, not a payment
/// failure: code catching <see cref="PaymentFailedException"/> should not expect it.
/// No funds are spent.
/// </remarks>
public class UnsupportedWalletException : L402Exception
{
    public string WalletReason { get; }

    public UnsupportedWalletException(string walletReason)
        : base($"Wallet cannot be used for L402: {walletReason}")
    {
        WalletReason = walletReason;
    }
}
