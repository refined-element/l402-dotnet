using L402Requests.Wallets;
using Microsoft.Extensions.DependencyInjection;

namespace L402Requests;

/// <summary>
/// Extension methods for registering L402 HTTP clients with DI.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Register a named HTTP client with L402 auto-payment support.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="name">The name for the HTTP client.</param>
    /// <param name="configure">Optional action to configure L402 options.</param>
    /// <returns>The IHttpClientBuilder for further configuration.</returns>
    public static IHttpClientBuilder AddL402HttpClient(
        this IServiceCollection services,
        string name,
        Action<L402Options>? configure = null)
    {
        var options = new L402Options();
        configure?.Invoke(options);

        // Register shared services as singletons
        var wallet = options.Wallet ?? WalletDetector.DetectWallet();
        var budget = options.BudgetEnabled ? new BudgetController(options) : null;
        var cache = new CredentialCache(options.CacheMaxSize, options.CacheTtlSeconds);

        services.AddSingleton<IWallet>(wallet);

        return services.AddHttpClient(name)
            .AddHttpMessageHandler(() => new L402DelegatingHandler(wallet, budget, cache));
    }

    /// <summary>
    /// Register a typed HTTP client with L402 auto-payment support.
    /// </summary>
    public static IHttpClientBuilder AddL402HttpClient<TClient>(
        this IServiceCollection services,
        Action<L402Options>? configure = null)
        where TClient : class
    {
        var options = new L402Options();
        configure?.Invoke(options);

        var wallet = options.Wallet ?? WalletDetector.DetectWallet();
        var budget = options.BudgetEnabled ? new BudgetController(options) : null;
        var cache = new CredentialCache(options.CacheMaxSize, options.CacheTtlSeconds);

        services.AddSingleton<IWallet>(wallet);

        return services.AddHttpClient<TClient>()
            .AddHttpMessageHandler(() => new L402DelegatingHandler(wallet, budget, cache));
    }
}
