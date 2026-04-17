using System.Runtime.Versioning;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;

[SupportedOSPlatform("windows")]
internal sealed class WindowsWifiController : IWifiController
{
    public Task<IReadOnlyList<WifiNetwork>> ScanAsync(CancellationToken cancellationToken)
        => WindowsNativeWifi.ScanAsync(TimeSpan.FromSeconds(8), cancellationToken);

    public async Task<string?> GetCurrentSsidAsync(CancellationToken cancellationToken)
    {
        var output = await ShellRunner.RunOrThrowAsync("netsh", "wlan show interfaces", cancellationToken);
        foreach (var line in output.Split('\n'))
        {
            var match = Regex.Match(line, @"^\s*SSID\s*:\s*(.+?)\s*$");
            if (match.Success && !line.Contains("BSSID", StringComparison.Ordinal))
            {
                var ssid = match.Groups[1].Value.Trim();
                return string.IsNullOrEmpty(ssid) ? null : ssid;
            }
        }

        return null;
    }

    public async Task ConnectAsync(string ssid, string? password, CancellationToken cancellationToken)
    {
        var (connectExit, connectStdout, _) = await ShellRunner.RunAsync(
            "netsh", $"wlan connect name=\"{ssid}\" ssid=\"{ssid}\"", cancellationToken);
        if (connectExit == 0 && !connectStdout.Contains("There is no profile", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var xml = BuildProfileXml(ssid, password);
        var profilePath = Path.Combine(Path.GetTempPath(), $"ecoplug-{Guid.NewGuid():N}.xml");
        await File.WriteAllTextAsync(profilePath, xml, new UTF8Encoding(false), cancellationToken);
        try
        {
            await ShellRunner.RunOrThrowAsync("netsh", $"wlan add profile filename=\"{profilePath}\" user=current", cancellationToken);
            await ShellRunner.RunOrThrowAsync("netsh", $"wlan connect name=\"{ssid}\" ssid=\"{ssid}\"", cancellationToken);
        }
        finally
        {
            try { File.Delete(profilePath); } catch { }
        }
    }

    public Task DisconnectAsync(CancellationToken cancellationToken)
        => ShellRunner.RunOrThrowAsync("netsh", "wlan disconnect", cancellationToken);

    public Task WaitForIPv4Async(string requiredPrefix, TimeSpan timeout, CancellationToken cancellationToken)
        => WifiController.WaitForAnyIPv4Async(requiredPrefix, timeout, cancellationToken);

    private static string BuildProfileXml(string ssid, string? password)
    {
        var escapedSsid = SecurityElement.Escape(ssid);
        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\"?>");
        sb.AppendLine("<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">");
        sb.AppendLine($"  <name>{escapedSsid}</name>");
        sb.AppendLine("  <SSIDConfig>");
        sb.AppendLine("    <SSID>");
        sb.AppendLine($"      <name>{escapedSsid}</name>");
        sb.AppendLine("    </SSID>");
        sb.AppendLine("  </SSIDConfig>");
        sb.AppendLine("  <connectionType>ESS</connectionType>");
        sb.AppendLine("  <connectionMode>manual</connectionMode>");
        sb.AppendLine("  <MSM>");
        sb.AppendLine("    <security>");
        sb.AppendLine("      <authEncryption>");
        sb.AppendLine($"        <authentication>{(password is null ? "open" : "WPA2PSK")}</authentication>");
        sb.AppendLine($"        <encryption>{(password is null ? "none" : "AES")}</encryption>");
        sb.AppendLine("        <useOneX>false</useOneX>");
        sb.AppendLine("      </authEncryption>");
        if (password is not null)
        {
            sb.AppendLine("      <sharedKey>");
            sb.AppendLine("        <keyType>passPhrase</keyType>");
            sb.AppendLine("        <protected>false</protected>");
            sb.AppendLine($"        <keyMaterial>{SecurityElement.Escape(password)}</keyMaterial>");
            sb.AppendLine("      </sharedKey>");
        }
        sb.AppendLine("    </security>");
        sb.AppendLine("  </MSM>");
        sb.AppendLine("</WLANProfile>");
        return sb.ToString();
    }
}
