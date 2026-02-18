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
