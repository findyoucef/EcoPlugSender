using System.Text.RegularExpressions;

internal sealed class MacWifiController : IWifiController
{
    private const string AirportPath = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport";

    public async Task<IReadOnlyList<WifiNetwork>> ScanAsync(CancellationToken cancellationToken)
    {
        var output = await ShellRunner.RunOrThrowAsync(AirportPath, "-s", cancellationToken);
        return ParseAirportScan(output);
    }

    public async Task<string?> GetCurrentSsidAsync(CancellationToken cancellationToken)
    {
        var iface = await GetWifiInterfaceAsync(cancellationToken);
        var output = await ShellRunner.RunOrThrowAsync("networksetup", $"-getairportnetwork {iface}", cancellationToken);
        var match = Regex.Match(output, @"Current Wi-Fi Network:\s*(.+?)\s*$", RegexOptions.Multiline);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    public async Task ConnectAsync(string ssid, string? password, CancellationToken cancellationToken)
    {
        var iface = await GetWifiInterfaceAsync(cancellationToken);
        var args = password is null
            ? $"-setairportnetwork {iface} \"{Escape(ssid)}\""
            : $"-setairportnetwork {iface} \"{Escape(ssid)}\" \"{Escape(password)}\"";
        await ShellRunner.RunOrThrowAsync("networksetup", args, cancellationToken);
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken)
    {
        var iface = await GetWifiInterfaceAsync(cancellationToken);
        await ShellRunner.RunAsync("networksetup", $"-setairportpower {iface} off", cancellationToken);
        await Task.Delay(1000, cancellationToken);
        await ShellRunner.RunAsync("networksetup", $"-setairportpower {iface} on", cancellationToken);
    }

    public Task WaitForIPv4Async(string requiredPrefix, TimeSpan timeout, CancellationToken cancellationToken)
        => WifiController.WaitForAnyIPv4Async(requiredPrefix, timeout, cancellationToken);

    private static IReadOnlyList<WifiNetwork> ParseAirportScan(string output)
    {
        var results = new List<WifiNetwork>();
        var lines = output.Split('\n');
        if (lines.Length <= 1)
        {
            return results;
        }

        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var match = Regex.Match(line, @"^\s*(.+?)\s+([0-9a-fA-F:]{17})\s+(-?\d+)\s+\S+\s+\S+\s+(.*)$");
            if (!match.Success)
            {
                continue;
            }

            var ssid = match.Groups[1].Value.Trim();
            var rssi = int.Parse(match.Groups[3].Value);
            var security = match.Groups[4].Value.Trim();
            var isOpen = security.Equals("NONE", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(security);
            var signal = Math.Max(0, Math.Min(100, 2 * (rssi + 100)));
            results.Add(new WifiNetwork(ssid, signal, isOpen));
        }

        return results;
    }

    private static async Task<string> GetWifiInterfaceAsync(CancellationToken cancellationToken)
    {
        var output = await ShellRunner.RunOrThrowAsync("networksetup", "-listallhardwareports", cancellationToken);
        var lines = output.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase) && i + 1 < lines.Length)
            {
                var match = Regex.Match(lines[i + 1], @"Device:\s*(\S+)");
                if (match.Success)
                {
                    return match.Groups[1].Value;
                }
            }
        }

        return "en0";
    }

    private static string Escape(string value) => value.Replace("\"", "\\\"");
}
