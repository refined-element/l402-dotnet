using L402Requests.Wallets;

namespace L402Requests;

/// <summary>
/// Configuration options for L402 HTTP clients.
/// </summary>
public class L402Options
{
    /// <summary>Maximum sats for a single payment (default: 1000).</summary>
    public int MaxSatsPerRequest { get; set; } = 1_000;

    /// <summary>Maximum sats in a sliding 1-hour window (default: 10000).</summary>
    public int MaxSatsPerHour { get; set; } = 10_000;

    /// <summary>Maximum sats in a sliding 24-hour window (default: 50000).</summary>
    public int MaxSatsPerDay { get; set; } = 50_000;

    /// <summary>
    /// If set, only pay invoices for requests to these domains.
    /// Null means all domains are allowed.
    /// </summary>
    public HashSet<string>? AllowedDomains { get; set; }

    /// <summary>
    /// Wallet adapter for paying invoices. If null, auto-detects from environment.
    /// </summary>
    public IWallet? Wallet { get; set; }

    /// <summary>
    /// Whether budget controls are enabled. Set to false to disable all limits.
    /// </summary>
    public bool BudgetEnabled { get; set; } = true;

    /// <summary>
    /// Maximum number of cached L402 credentials (default: 256).
    /// </summary>
    public int CacheMaxSize { get; set; } = 256;

    /// <summary>
    /// Default TTL for cached credentials in seconds (default: 3600 = 1 hour).
    /// Set to null to disable expiration.
    /// </summary>
    public double? CacheTtlSeconds { get; set; } = 3600.0;
}
