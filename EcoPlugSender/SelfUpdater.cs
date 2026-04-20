using System.Formats.Tar;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

internal static class SelfUpdater
{
    private const string RepoOwner = "findyoucef";
    private const string RepoName = "eco-releases";
    private const string UserAgent = "EcoPlugSender-eco";

    public static string CurrentVersion =>
        typeof(SelfUpdater).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(SelfUpdater).Assembly.GetName().Version?.ToString()
        ?? "0.0.0";

    public static async Task<int> RunAsync(bool checkOnly)
    {
        var currentExe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(currentExe))
        {
            Console.Error.WriteLine("Cannot determine running executable path.");
            return 2;
        }

        var exeName = Path.GetFileNameWithoutExtension(currentExe);
        if (!string.Equals(exeName, "eco", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine($"eco update only works against the published eco binary. Current process is {currentExe} (likely `dotnet run` in development).");
            return 2;
        }

        var current = NormalizeVersion(CurrentVersion);
        Console.WriteLine($"Current version: {current}");

        using var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);

        string latestJson;
        try
        {
            latestJson = await http.GetStringAsync($"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases/latest");
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"Failed to reach GitHub API: {ex.Message}");
            return 3;
        }

        var latestTag = ExtractTag(latestJson);
        var latest = NormalizeVersion(latestTag);
        Console.WriteLine($"Latest release: {latestTag}");

        if (string.Equals(current, latest, StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Already up to date.");
            return 0;
        }

        if (checkOnly)
        {
            Console.WriteLine($"Update available: {current} -> {latest}. Run `eco update` to install.");
            return 0;
        }

        var assetName = PlatformAssetName();
        var assetUrl = ExtractAssetUrl(latestJson, assetName)
            ?? throw new InvalidOperationException($"Release {latestTag} has no asset named {assetName}.");
        Console.WriteLine($"Downloading {assetName}...");

        var tempDir = Directory.CreateTempSubdirectory("eco-update-").FullName;
        try
        {
            var archivePath = Path.Combine(tempDir, assetName);
            await using (var resp = await http.GetStreamAsync(assetUrl))
            await using (var fs = File.Create(archivePath))
            {
                await resp.CopyToAsync(fs);
            }

            var extractedBinary = ExtractBinary(archivePath, tempDir);
            ReplaceRunningExe(currentExe, extractedBinary);
            Console.WriteLine($"Updated eco to {latest}.");
            return 0;
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { /* best effort */ }
        }
    }

    public static void CleanupStaleBackup()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe)) return;
        var oldPath = exe + ".old";
        if (File.Exists(oldPath))
        {
            try { File.Delete(oldPath); } catch { /* held by a previous run still exiting; retry next time */ }
        }
    }

    private static string NormalizeVersion(string v)
    {
        var trimmed = v.TrimStart('v', 'V').Trim();
        var plus = trimmed.IndexOf('+');
        if (plus >= 0) trimmed = trimmed[..plus];
        return trimmed;
    }

    private static string ExtractTag(string json)
    {
        var m = Regex.Match(json, "\"tag_name\"\\s*:\\s*\"([^\"]+)\"");
        if (!m.Success) throw new InvalidOperationException("Could not find tag_name in release response.");
        return m.Groups[1].Value;
    }

    private static string? ExtractAssetUrl(string json, string assetName)
    {
        var pattern = "\"browser_download_url\"\\s*:\\s*\"([^\"]*" + Regex.Escape(assetName) + ")\"";
        var m = Regex.Match(json, pattern);
        return m.Success ? m.Groups[1].Value : null;
    }

    private static string PlatformAssetName()
    {
        var arch = RuntimeInformation.ProcessArchitecture;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && arch == Architecture.X64)
            return "eco-win-x64.zip";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && arch == Architecture.X64)
            return "eco-linux-x64.tar.gz";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) && arch == Architecture.Arm64)
            return "eco-osx-arm64.tar.gz";
        throw new InvalidOperationException($"No release asset for {RuntimeInformation.OSDescription} / {arch}.");
    }

    private static string ExtractBinary(string archivePath, string destDir)
    {
        var extractDir = Path.Combine(destDir, "extracted");
        Directory.CreateDirectory(extractDir);

        if (archivePath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            ZipFile.ExtractToDirectory(archivePath, extractDir);
            var exe = Path.Combine(extractDir, "eco.exe");
            if (!File.Exists(exe))
                throw new InvalidOperationException($"Archive {archivePath} did not contain eco.exe at top level.");
            return exe;
        }

        if (archivePath.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase))
        {
            using (var fs = File.OpenRead(archivePath))
            using (var gz = new GZipStream(fs, CompressionMode.Decompress))
            {
                TarFile.ExtractToDirectory(gz, extractDir, overwriteFiles: true);
            }
            var binary = Path.Combine(extractDir, "eco");
            if (!File.Exists(binary))
                throw new InvalidOperationException($"Archive {archivePath} did not contain eco at top level.");
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                File.SetUnixFileMode(binary,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                    | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                    | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            }
            return binary;
        }

        throw new InvalidOperationException($"Unknown archive format: {archivePath}");
    }

    private static void ReplaceRunningExe(string currentExe, string newBinary)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var oldPath = currentExe + ".old";
            if (File.Exists(oldPath))
            {
                try { File.Delete(oldPath); } catch { /* in use from a prior update still exiting */ }
            }
            File.Move(currentExe, oldPath);
            File.Move(newBinary, currentExe);
        }
        else
        {
            File.Move(newBinary, currentExe, overwrite: true);
        }
    }
}
