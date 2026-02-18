using System.Text.Json;

namespace L402Requests.Wallets;

/// <summary>
/// Auto-detect a wallet from environment variables or config file.
/// Priority: LND > NWC > Strike > OpenNode (same as Python/MCP).
/// </summary>
public static class WalletDetector
{
    private static readonly string ConfigPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".lightning-enable", "config.json");

    private static readonly string[] DefaultPriority = ["lnd", "nwc", "strike", "opennode"];

    private static readonly Dictionary<string, string> PriorityAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["strike"] = "strike",
        ["opennode"] = "opennode",
        ["nwc"] = "nwc",
        ["lnd"] = "lnd",
        ["nostr"] = "nwc",
    };

    /// <summary>
    /// Auto-detect a wallet from environment variables or config file.
    /// </summary>
    /// <returns>A configured wallet adapter.</returns>
    /// <exception cref="NoWalletException">If no wallet credentials are found.</exception>
    public static IWallet DetectWallet()
    {
        var (walletsConfig, priority) = LoadConfig();

        foreach (var name in priority)
        {
            var wallet = TryBuildWallet(name, walletsConfig);
            if (wallet is not null)
                return wallet;
        }

        throw new NoWalletException();
    }

    private static (Dictionary<string, string> walletsConfig, string[] priority) LoadConfig()
    {
        var walletsConfig = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var priority = DefaultPriority.ToArray();

        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (root.TryGetProperty("wallets", out var wallets))
                {
                    foreach (var prop in wallets.EnumerateObject())
                    {
                        if (prop.Value.ValueKind == JsonValueKind.String)
                            walletsConfig[prop.Name] = prop.Value.GetString()!;
                    }

                    // Check for priority override
                    if (wallets.TryGetProperty("priority", out var priorityEl) &&
                        priorityEl.ValueKind == JsonValueKind.String)
                    {
                        var preferred = priorityEl.GetString()!;
                        if (PriorityAliases.TryGetValue(preferred, out var preferredName))
                        {
                            var newPriority = new List<string> { preferredName };
                            foreach (var p in DefaultPriority)
                            {
                                if (p != preferredName)
                                    newPriority.Add(p);
                            }
                            priority = newPriority.ToArray();
                        }
                    }
                }
            }
        }
        catch (Exception)
        {
            // Config file errors are not fatal
        }

        return (walletsConfig, priority);
    }

    private static IWallet? TryBuildWallet(string name, Dictionary<string, string> walletsConfig)
    {
        return name switch
        {
            "lnd" => TryBuildLnd(),
            "nwc" => TryBuildNwc(walletsConfig),
            "strike" => TryBuildStrike(walletsConfig),
            "opennode" => TryBuildOpenNode(walletsConfig),
            _ => null,
        };
    }

    private static IWallet? TryBuildLnd()
    {
        var host = Environment.GetEnvironmentVariable("LND_REST_HOST") ?? "";
        var macaroon = Environment.GetEnvironmentVariable("LND_MACAROON_HEX") ?? "";

        if (IsRealValue(host) && IsRealValue(macaroon))
        {
            var tlsCertPath = Environment.GetEnvironmentVariable("LND_TLS_CERT_PATH");
            return new LndWallet(host, macaroon, tlsCertPath);
        }

        return null;
    }

    private static IWallet? TryBuildNwc(Dictionary<string, string> walletsConfig)
    {
        var connStr = ResolveCredential("NWC_CONNECTION_STRING", "nwcConnectionString", walletsConfig);
        if (!string.IsNullOrEmpty(connStr))
            return new NwcWallet(connStr);
        return null;
    }

    private static IWallet? TryBuildStrike(Dictionary<string, string> walletsConfig)
    {
        var apiKey = ResolveCredential("STRIKE_API_KEY", "strikeApiKey", walletsConfig);
        if (!string.IsNullOrEmpty(apiKey))
            return new StrikeWallet(apiKey);
        return null;
    }

    private static IWallet? TryBuildOpenNode(Dictionary<string, string> walletsConfig)
    {
        var apiKey = ResolveCredential("OPENNODE_API_KEY", "openNodeApiKey", walletsConfig);
        if (!string.IsNullOrEmpty(apiKey))
            return new OpenNodeWallet(apiKey);
        return null;
    }

    private static string ResolveCredential(string envVar, string configKey, Dictionary<string, string> walletsConfig)
    {
        var val = Environment.GetEnvironmentVariable(envVar) ?? "";
        if (IsRealValue(val))
            return val;
        return walletsConfig.TryGetValue(configKey, out var configVal) ? configVal : "";
    }

    private static bool IsRealValue(string? val)
    {
        if (string.IsNullOrEmpty(val))
            return false;
        return !val.StartsWith("${");
    }
}
