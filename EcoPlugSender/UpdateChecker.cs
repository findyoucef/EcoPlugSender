using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

internal static class UpdateChecker
{
    private const string RepoOwner = "findyoucef";
    private const string RepoName = "eco-releases";
    private const string UserAgent = "EcoPlugSender-eco";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(24);

    public static void FireBackgroundCheckIfDue()
    {
        if (!ShouldRun()) return;

        var cache = ReadCache();
        if (cache is not null && DateTime.UtcNow - cache.CheckedAt < CacheTtl) return;

        _ = Task.Run(async () =>
        {
            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
                var json = await http.GetStringAsync($"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases/latest");
                var m = Regex.Match(json, "\"tag_name\"\\s*:\\s*\"([^\"]+)\"");
                if (!m.Success) return;
                WriteCache(new Cache(DateTime.UtcNow, m.Groups[1].Value));
            }
            catch { /* silent — update check is best-effort */ }
        });
    }

    public static void PrintBannerIfAvailable()
    {
        if (!ShouldRun()) return;

        var cache = ReadCache();
        if (cache is null) return;

        var current = NormalizeVersion(CurrentVersion());
        var latest = NormalizeVersion(cache.LatestTag);
        if (string.Equals(current, latest, StringComparison.OrdinalIgnoreCase)) return;
        if (!IsNewer(current, latest)) return;

        Console.Error.WriteLine();
        Console.Error.WriteLine($"A new eco release is available: v{current} -> {cache.LatestTag}. Run `eco update` to install.");
    }

    private static bool ShouldRun()
    {
        if (Environment.GetEnvironmentVariable("ECO_NO_UPDATE_CHECK") == "1") return false;
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe)) return false;
        var name = Path.GetFileNameWithoutExtension(exe);
        return string.Equals(name, "eco", StringComparison.OrdinalIgnoreCase);
    }

    private static string CurrentVersion()
    {
        var v = typeof(UpdateChecker).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(UpdateChecker).Assembly.GetName().Version?.ToString()
            ?? "0.0.0";
        return v;
    }

    private static string NormalizeVersion(string v)
    {
        var trimmed = v.TrimStart('v', 'V').Trim();
        var plus = trimmed.IndexOf('+');
        if (plus >= 0) trimmed = trimmed[..plus];
        return trimmed;
    }

    private static bool IsNewer(string current, string latest)
    {
        return !string.Equals(current, latest, StringComparison.OrdinalIgnoreCase);
    }

    private static string CacheFilePath()
    {
        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrEmpty(baseDir))
        {
            baseDir = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Path.GetTempPath()
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        }
        return Path.Combine(baseDir, "eco", "update-check.txt");
    }

    private sealed record Cache(DateTime CheckedAt, string LatestTag);

    private static Cache? ReadCache()
    {
        try
        {
            var path = CacheFilePath();
            if (!File.Exists(path)) return null;
            var lines = File.ReadAllLines(path);
            DateTime? checkedAt = null;
            string? tag = null;
            foreach (var line in lines)
            {
                var eq = line.IndexOf('=');
                if (eq < 0) continue;
                var key = line[..eq];
                var value = line[(eq + 1)..];
                if (key == "checked_at" && long.TryParse(value, out var unix))
                    checkedAt = DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime;
                else if (key == "latest_tag")
                    tag = value;
            }
            if (checkedAt is null || tag is null) return null;
            return new Cache(checkedAt.Value, tag);
        }
        catch
        {
            return null;
        }
    }

    private static void WriteCache(Cache cache)
    {
        try
        {
            var path = CacheFilePath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var unix = new DateTimeOffset(cache.CheckedAt, TimeSpan.Zero).ToUnixTimeSeconds();
            File.WriteAllLines(path, new[]
            {
                $"checked_at={unix}",
                $"latest_tag={cache.LatestTag}",
            });
        }
        catch { /* silent — cache is best-effort */ }
    }
}
