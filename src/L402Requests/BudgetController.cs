using System.Collections.Concurrent;

namespace L402Requests;

/// <summary>
/// Configurable spending limits for L402 payments.
/// Thread-safe. Uses sliding windows for hourly and daily limits.
/// </summary>
public sealed class BudgetController
{
    private readonly int _maxSatsPerRequest;
    private readonly int _maxSatsPerHour;
    private readonly int _maxSatsPerDay;
    private readonly HashSet<string>? _allowedDomains;
    private readonly ConcurrentQueue<(DateTimeOffset Timestamp, int AmountSats)> _payments = new();
    private readonly object _lock = new();

    public BudgetController(
        int maxSatsPerRequest = 1_000,
        int maxSatsPerHour = 10_000,
        int maxSatsPerDay = 50_000,
        HashSet<string>? allowedDomains = null)
    {
        _maxSatsPerRequest = maxSatsPerRequest;
        _maxSatsPerHour = maxSatsPerHour;
        _maxSatsPerDay = maxSatsPerDay;
        _allowedDomains = allowedDomains != null
            ? new HashSet<string>(allowedDomains, StringComparer.OrdinalIgnoreCase)
            : null;
    }

    public BudgetController(L402Options options)
        : this(options.MaxSatsPerRequest, options.MaxSatsPerHour, options.MaxSatsPerDay, options.AllowedDomains)
    {
    }

    /// <summary>
    /// Verify a payment is within budget. Throws if not.
    /// </summary>
    /// <param name="amountSats">The invoice amount in satoshis.</param>
    /// <param name="domain">The domain the request is going to.</param>
    public void Check(int amountSats, string? domain = null)
    {
        // Domain allowlist check
        if (_allowedDomains is not null && !string.IsNullOrEmpty(domain))
        {
            if (!_allowedDomains.Contains(domain))
                throw new DomainNotAllowedException(domain);
        }

        // Per-request limit
        if (amountSats > _maxSatsPerRequest)
            throw new BudgetExceededException("per_request", _maxSatsPerRequest, 0, amountSats);

        var now = DateTimeOffset.UtcNow;

        lock (_lock)
        {
            Prune(now);

            // Hourly limit
            var hourAgo = now.AddHours(-1);
            var spentHour = GetSpentSince(hourAgo);
            if (spentHour + amountSats > _maxSatsPerHour)
                throw new BudgetExceededException("per_hour", _maxSatsPerHour, spentHour, amountSats);

            // Daily limit
            var dayAgo = now.AddDays(-1);
            var spentDay = GetSpentSince(dayAgo);
            if (spentDay + amountSats > _maxSatsPerDay)
                throw new BudgetExceededException("per_day", _maxSatsPerDay, spentDay, amountSats);
        }
    }

    /// <summary>
    /// Record a successful payment against the budget.
    /// </summary>
    public void RecordPayment(int amountSats)
    {
        _payments.Enqueue((DateTimeOffset.UtcNow, amountSats));
    }

    /// <summary>Total sats spent in the last hour.</summary>
    public int SpentLastHour()
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
        return GetSpentSince(cutoff);
    }

    /// <summary>Total sats spent in the last 24 hours.</summary>
    public int SpentLastDay()
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-1);
        return GetSpentSince(cutoff);
    }

    private int GetSpentSince(DateTimeOffset since)
    {
        var total = 0;
        foreach (var (ts, amt) in _payments)
        {
            if (ts >= since)
                total += amt;
        }
        return total;
    }

    private void Prune(DateTimeOffset now)
    {
        var cutoff = now.AddDays(-1);
        while (_payments.TryPeek(out var oldest) && oldest.Timestamp < cutoff)
        {
            _payments.TryDequeue(out _);
        }
    }
}
