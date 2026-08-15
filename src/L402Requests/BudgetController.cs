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

    // In-flight reservations: id -> reserved sats. A reservation is a spend that has
    // passed the caps and is committed-in-intent but not yet settled (the wallet call is
    // still outstanding). It counts fully against the hour/day caps so two concurrent
    // payments cannot both pass a check against the same pre-payment total. Guarded by
    // _lock, together with the window evaluation, so evaluate+reserve is atomic.
    private readonly Dictionary<long, int> _reservations = new();
    private long _nextReservationId;

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
    /// <remarks>
    /// Read-only preview: it does NOT hold a slot. Prefer the reserve/commit lifecycle
    /// (<see cref="TryReserve"/> → <see cref="Commit"/>/<see cref="Release"/>) around an
    /// actual payment — Check followed by a later record is a check-then-pay-then-record
    /// TOCTOU race under concurrency, because the lock is released before the payment and
    /// the spend is recorded only afterwards. Kept for backward compatibility.
    /// </remarks>
    /// <param name="amountSats">The invoice amount in satoshis.</param>
    /// <param name="domain">The domain the request is going to.</param>
    public void Check(int amountSats, string? domain = null)
    {
        ValidateDomainAndPerRequest(amountSats, domain);

        var now = DateTimeOffset.UtcNow;
        lock (_lock)
        {
            Prune(now);
            EnforceWindowLimits(now, amountSats);
        }
    }

    /// <summary>
    /// Atomically reserve budget for a payment about to be made. Evaluates the domain
    /// allowlist and the per-request / hourly / daily caps — counting other in-flight
    /// reservations — under a single lock, and, if within limits, records a reservation
    /// and returns its id. Throws (same exceptions as <see cref="Check"/>) if refused.
    /// </summary>
    /// <remarks>
    /// This is the enforcement path. Because the evaluation and the reservation happen
    /// together under one lock, two concurrent reservations cannot both pass against the
    /// same pre-payment total. The caller pays OUTSIDE the lock, then calls
    /// <see cref="Commit"/> on success or <see cref="Release"/> on failure. A reservation
    /// counts fully against the hourly and daily windows until committed or released.
    /// </remarks>
    /// <param name="amountSats">The invoice amount in satoshis.</param>
    /// <param name="domain">The domain the request is going to.</param>
    /// <returns>A reservation id to pass to <see cref="Commit"/> or <see cref="Release"/>.</returns>
    public long TryReserve(int amountSats, string? domain = null)
    {
        ValidateDomainAndPerRequest(amountSats, domain);

        var now = DateTimeOffset.UtcNow;
        lock (_lock)
        {
            Prune(now);
            EnforceWindowLimits(now, amountSats);

            var id = ++_nextReservationId;
            _reservations[id] = amountSats;
            return id;
        }
    }

    /// <summary>
    /// Commit a reservation: record the settled spend into the budget window and drop the
    /// reservation. Pass the actual amount paid (principal, plus routing fee if the wallet
    /// surfaces one). No-op if the id is unknown (already committed/released).
    /// </summary>
    public void Commit(long reservationId, int actualAmountSats)
    {
        lock (_lock)
        {
            _reservations.Remove(reservationId);
            _payments.Enqueue((DateTimeOffset.UtcNow, actualAmountSats));
        }
    }

    /// <summary>
    /// Release a reservation with no spend (payment failed or was not attempted), freeing
    /// the reserved budget. No-op if the id is unknown (already committed/released).
    /// </summary>
    public void Release(long reservationId)
    {
        lock (_lock)
        {
            _reservations.Remove(reservationId);
        }
    }

    /// <summary>
    /// Record a successful payment against the budget.
    /// </summary>
    /// <remarks>
    /// Kept for backward compatibility. New code should use the reserve/commit lifecycle
    /// so the spend is reserved atomically before the wallet call rather than recorded
    /// after it (see <see cref="Check"/> remarks for the race this avoids).
    /// </remarks>
    public void RecordPayment(int amountSats)
    {
        _payments.Enqueue((DateTimeOffset.UtcNow, amountSats));
    }

    /// <summary>Domain allowlist + per-request checks. No lock needed (immutable inputs).</summary>
    private void ValidateDomainAndPerRequest(int amountSats, string? domain)
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
    }

    /// <summary>
    /// Enforce the hourly/daily windows, counting settled spend AND in-flight reservations.
    /// Must be called while holding <see cref="_lock"/>.
    /// </summary>
    private void EnforceWindowLimits(DateTimeOffset now, int amountSats)
    {
        var reserved = SumReservations();

        // Hourly limit
        var hourAgo = now.AddHours(-1);
        var spentHour = GetSpentSince(hourAgo) + reserved;
        if (spentHour + amountSats > _maxSatsPerHour)
            throw new BudgetExceededException("per_hour", _maxSatsPerHour, spentHour, amountSats);

        // Daily limit
        var dayAgo = now.AddDays(-1);
        var spentDay = GetSpentSince(dayAgo) + reserved;
        if (spentDay + amountSats > _maxSatsPerDay)
            throw new BudgetExceededException("per_day", _maxSatsPerDay, spentDay, amountSats);
    }

    private int SumReservations()
    {
        var total = 0;
        foreach (var amt in _reservations.Values)
            total += amt;
        return total;
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
