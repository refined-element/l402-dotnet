using FluentAssertions;

namespace L402Requests.Tests;

public class CredentialCacheTests
{
    [Fact]
    public void Put_And_Get_ReturnsCachedCredential()
    {
        var cache = new CredentialCache();
        cache.Put("example.com", "/api/v1/data", "mac123", "pre456");

        var cred = cache.Get("example.com", "/api/v1/data");
        cred.Should().NotBeNull();
        cred!.Macaroon.Should().Be("mac123");
        cred.Preimage.Should().Be("pre456");
    }

    [Fact]
    public void Get_SamePathPrefix_ReturnsCachedCredential()
    {
        var cache = new CredentialCache();
        cache.Put("example.com", "/api/v1/foo", "mac123", "pre456");

        // Different path but same first two segments
        var cred = cache.Get("example.com", "/api/v1/bar");
        cred.Should().NotBeNull();
        cred!.Macaroon.Should().Be("mac123");
    }

    [Fact]
    public void Get_DifferentDomain_ReturnsNull()
    {
        var cache = new CredentialCache();
        cache.Put("example.com", "/api/data", "mac123", "pre456");

        var cred = cache.Get("other.com", "/api/data");
        cred.Should().BeNull();
    }

    [Fact]
    public void Get_DifferentPathPrefix_ReturnsNull()
    {
        var cache = new CredentialCache();
        cache.Put("example.com", "/api/v1/data", "mac123", "pre456");

        // Different prefix: /api/v2 vs /api/v1
        var cred = cache.Get("example.com", "/api/v2/data");
        cred.Should().BeNull();
    }

    [Fact]
    public void Get_DomainCaseInsensitive()
    {
        var cache = new CredentialCache();
        cache.Put("Example.COM", "/api/v1/data", "mac123", "pre456");

        var cred = cache.Get("example.com", "/api/v1/data");
        cred.Should().NotBeNull();
    }

    [Fact]
    public void LruEviction_OldestRemoved()
    {
        var cache = new CredentialCache(maxSize: 2);
        cache.Put("a.com", "/path", "mac_a", "pre_a");
        cache.Put("b.com", "/path", "mac_b", "pre_b");
        cache.Put("c.com", "/path", "mac_c", "pre_c"); // Should evict a.com

        cache.Get("a.com", "/path").Should().BeNull();
        cache.Get("b.com", "/path").Should().NotBeNull();
        cache.Get("c.com", "/path").Should().NotBeNull();
        cache.Count.Should().Be(2);
    }

    [Fact]
    public void LruEviction_AccessRefreshesOrder()
    {
        var cache = new CredentialCache(maxSize: 2);
        cache.Put("a.com", "/path", "mac_a", "pre_a");
        cache.Put("b.com", "/path", "mac_b", "pre_b");

        // Access a.com to refresh its position
        cache.Get("a.com", "/path");

        cache.Put("c.com", "/path", "mac_c", "pre_c"); // Should evict b.com (least recently used)

        cache.Get("a.com", "/path").Should().NotBeNull();
        cache.Get("b.com", "/path").Should().BeNull();
        cache.Get("c.com", "/path").Should().NotBeNull();
    }

    [Fact]
    public void TtlExpiration_ExpiredCredentialReturnsNull()
    {
        var cache = new CredentialCache(defaultTtlSeconds: null);

        // Put with an already-expired timestamp
        cache.Put("example.com", "/api/data", "mac123", "pre456",
            expiresAt: DateTimeOffset.UtcNow.AddSeconds(-1));

        var cred = cache.Get("example.com", "/api/data");
        cred.Should().BeNull();
    }

    [Fact]
    public void Clear_RemovesAll()
    {
        var cache = new CredentialCache();
        cache.Put("a.com", "/path", "mac_a", "pre_a");
        cache.Put("b.com", "/path", "mac_b", "pre_b");

        cache.Clear();
        cache.Count.Should().Be(0);
        cache.Get("a.com", "/path").Should().BeNull();
    }

    [Fact]
    public void AuthorizationHeader_FormattedCorrectly()
    {
        var cache = new CredentialCache();
        var cred = cache.Put("example.com", "/api", "mac123", "pre456");

        cred.AuthorizationHeader.Should().Be("L402 mac123:pre456");
    }

    [Fact]
    public void Put_UpdatesExistingEntry()
    {
        var cache = new CredentialCache();
        cache.Put("example.com", "/api/v1/data", "mac_old", "pre_old");
        cache.Put("example.com", "/api/v1/data", "mac_new", "pre_new");

        var cred = cache.Get("example.com", "/api/v1/data");
        cred.Should().NotBeNull();
        cred!.Macaroon.Should().Be("mac_new");
        cache.Count.Should().Be(1);
    }

    [Fact]
    public void CacheKey_NormalizesCorrectly()
    {
        CredentialCache.CacheKey("Example.COM", "/api/v1/data")
            .Should().Be("example.com|/api/v1");

        CredentialCache.CacheKey("test.com", "/single")
            .Should().Be("test.com|/single");

        CredentialCache.CacheKey("test.com", "/")
            .Should().Be("test.com|/");
    }
}
