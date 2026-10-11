using System.Net.Http.Headers;
using System.Reflection;

namespace L402Requests;

/// <summary>
/// The <c>User-Agent</c> sent on every HTTP request the library issues
/// (<c>L402Requests/&lt;version&gt;</c>). Server-side analytics attribute traffic by it,
/// so it carries the real package version rather than a hand-maintained literal.
/// </summary>
/// <remarks>
/// Applied per request and only when absent, so a caller that set its own
/// <c>User-Agent</c> (on the request or on the <see cref="HttpClient"/> it supplied) wins,
/// and a caller-supplied <see cref="HttpClient"/> is never mutated.
/// </remarks>
internal static class UserAgent
{
    /// <summary>Product token. Keep exactly this spelling: server-side analytics match on it.</summary>
    public const string ProductToken = "L402Requests";

    private const string HeaderName = "User-Agent";

    /// <summary>The package version, without any <c>+commit</c> source-revision suffix.</summary>
    public static string Version { get; } = ResolveVersion(typeof(UserAgent).Assembly);

    /// <summary>The full header value: <c>L402Requests/&lt;version&gt;</c>.</summary>
    public static string Value { get; } = $"{ProductToken}/{Version}";

    /// <summary>
    /// Add the library <c>User-Agent</c> to <paramref name="request"/> unless the request, or
    /// the default headers of the <see cref="HttpClient"/> that will send it, already carry one.
    /// </summary>
    internal static void ApplyIfAbsent(HttpRequestMessage request, HttpRequestHeaders? clientDefaults = null)
    {
        if (request.Headers.Contains(HeaderName))
            return;
        if (clientDefaults is not null && clientDefaults.Contains(HeaderName))
            return;
        request.Headers.TryAddWithoutValidation(HeaderName, Value);
    }

    /// <summary>
    /// Set the library <c>User-Agent</c> on an <see cref="HttpClient"/> the library itself
    /// created and owns. Never call this on a caller-supplied client.
    /// </summary>
    internal static void ApplyToOwnedClient(HttpClient ownedClient)
    {
        if (!ownedClient.DefaultRequestHeaders.Contains(HeaderName))
            ownedClient.DefaultRequestHeaders.TryAddWithoutValidation(HeaderName, Value);
    }

    internal static string ResolveVersion(Assembly assembly)
        => ResolveVersion(
            assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
            assembly.GetName().Version);

    internal static string ResolveVersion(string? informational, Version? assemblyVersion)
    {
        if (!string.IsNullOrWhiteSpace(informational))
        {
            var plus = informational.IndexOf('+');
            var trimmed = (plus >= 0 ? informational[..plus] : informational).Trim();
            if (trimmed.Length > 0)
                return trimmed;
        }

        return assemblyVersion is not null ? assemblyVersion.ToString(3) : "0.0.0";
    }
}
