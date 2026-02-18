using System.Text.Json;

namespace L402Requests;

/// <summary>
/// A single L402 payment event.
/// </summary>
public sealed record PaymentRecord(
    string Domain,
    string Path,
    int AmountSats,
    string Preimage,
    DateTimeOffset Timestamp,
    bool Success);

/// <summary>
/// Records all L402 payments for introspection and auditing.
/// </summary>
public sealed class SpendingLog
{
    private readonly List<PaymentRecord> _records = new();
    private readonly object _lock = new();

    /// <summary>
    /// Record a payment attempt.
    /// </summary>
    public PaymentRecord Record(string domain, string path, int amountSats, string preimage, bool success = true)
    {
        var record = new PaymentRecord(domain, path, amountSats, preimage, DateTimeOffset.UtcNow, success);
        lock (_lock)
        {
            _records.Add(record);
        }
        return record;
    }

    /// <summary>
    /// Get a copy of all payment records.
    /// </summary>
    public IReadOnlyList<PaymentRecord> Records
    {
        get
        {
            lock (_lock)
                return _records.ToList();
        }
    }

    /// <summary>Total sats spent across all successful payments.</summary>
    public int TotalSpent()
    {
        lock (_lock)
            return _records.Where(r => r.Success).Sum(r => r.AmountSats);
    }

    /// <summary>Total sats spent in the last hour.</summary>
    public int SpentLastHour()
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
        lock (_lock)
            return _records.Where(r => r.Success && r.Timestamp >= cutoff).Sum(r => r.AmountSats);
    }

    /// <summary>Total sats spent in the last 24 hours.</summary>
    public int SpentToday()
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-1);
        lock (_lock)
            return _records.Where(r => r.Success && r.Timestamp >= cutoff).Sum(r => r.AmountSats);
    }

    /// <summary>Total sats spent per domain.</summary>
    public Dictionary<string, int> ByDomain()
    {
        lock (_lock)
            return _records
                .Where(r => r.Success)
                .GroupBy(r => r.Domain)
                .ToDictionary(g => g.Key, g => g.Sum(r => r.AmountSats));
    }

    /// <summary>Serialize all records to JSON.</summary>
    public string ToJson()
    {
        lock (_lock)
            return JsonSerializer.Serialize(_records, new JsonSerializerOptions { WriteIndented = true });
    }

    public int Count
    {
        get
        {
            lock (_lock)
                return _records.Count;
        }
    }
}
