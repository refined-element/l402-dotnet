namespace L402Requests;

/// <summary>
/// A cached L402 credential (macaroon + preimage).
/// </summary>
public sealed record L402Credential(
    string Macaroon,
    string Preimage,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt)
{
    public bool IsExpired => ExpiresAt.HasValue && DateTimeOffset.UtcNow >= ExpiresAt.Value;

    public string AuthorizationHeader => $"L402 {Macaroon}:{Preimage}";
}

/// <summary>
/// Thread-safe LRU cache for L402 credentials, keyed by (domain, path_prefix).
/// </summary>
public sealed class CredentialCache
{
    private readonly int _maxSize;
    private readonly double? _defaultTtlSeconds;
    private readonly LinkedList<(string Key, L402Credential Credential)> _list = new();
    private readonly Dictionary<string, LinkedListNode<(string Key, L402Credential Credential)>> _map = new();
    private readonly object _lock = new();

    public CredentialCache(int maxSize = 256, double? defaultTtlSeconds = 3600.0)
    {
        _maxSize = maxSize;
        _defaultTtlSeconds = defaultTtlSeconds;
    }

    /// <summary>
    /// Retrieve a cached credential for the given domain and path.
    /// </summary>
    public L402Credential? Get(string domain, string path)
    {
        var key = CacheKey(domain, path);
        lock (_lock)
        {
            if (!_map.TryGetValue(key, out var node))
                return null;

            if (node.Value.Credential.IsExpired)
            {
                _list.Remove(node);
                _map.Remove(key);
                return null;
            }

            // Move to front (most recently used)
            _list.Remove(node);
            _list.AddFirst(node);
            return node.Value.Credential;
        }
    }

    /// <summary>
    /// Store a credential in the cache.
    /// </summary>
    public L402Credential Put(string domain, string path, string macaroon, string preimage, DateTimeOffset? expiresAt = null)
    {
        var key = CacheKey(domain, path);

        if (!expiresAt.HasValue && _defaultTtlSeconds.HasValue)
            expiresAt = DateTimeOffset.UtcNow.AddSeconds(_defaultTtlSeconds.Value);

        var cred = new L402Credential(macaroon, preimage, DateTimeOffset.UtcNow, expiresAt);

        lock (_lock)
        {
            // Remove existing entry if present
            if (_map.TryGetValue(key, out var existing))
            {
                _list.Remove(existing);
                _map.Remove(key);
            }

            var node = _list.AddFirst((key, cred));
            _map[key] = node;

            // Evict oldest if over capacity
            while (_list.Count > _maxSize)
            {
                var last = _list.Last!;
                _map.Remove(last.Value.Key);
                _list.RemoveLast();
            }
        }

        return cred;
    }

    /// <summary>
    /// Remove all cached credentials.
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _list.Clear();
            _map.Clear();
        }
    }

    public int Count
    {
        get
        {
            lock (_lock)
                return _map.Count;
        }
    }

    /// <summary>
    /// Normalize domain and path into a cache key.
    /// Groups paths by first two segments: /api/v1/anything -> /api/v1
    /// </summary>
    internal static string CacheKey(string domain, string path)
    {
        var normalizedDomain = domain.ToLowerInvariant().Trim();
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var prefix = parts.Length >= 2
            ? "/" + parts[0] + "/" + parts[1]
            : "/" + string.Join("/", parts);
        return $"{normalizedDomain}|{prefix}";
    }
}
