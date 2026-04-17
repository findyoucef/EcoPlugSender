internal sealed class LinuxWifiController : IWifiController
{
    public async Task<IReadOnlyList<WifiNetwork>> ScanAsync(CancellationToken cancellationToken)
    {
        await ShellRunner.RunAsync("nmcli", "device wifi rescan", cancellationToken);
        await Task.Delay(1500, cancellationToken);
        var output = await ShellRunner.RunOrThrowAsync("nmcli", "-t -f SSID,SIGNAL,SECURITY device wifi list", cancellationToken);
        return ParseNmcliScan(output);
    }

    public async Task<string?> GetCurrentSsidAsync(CancellationToken cancellationToken)
    {
        var output = await ShellRunner.RunOrThrowAsync("nmcli", "-t -f ACTIVE,SSID device wifi list", cancellationToken);
        foreach (var line in output.Split('\n'))
        {
            var parts = SplitNmcli(line);
            if (parts.Length >= 2 && parts[0].Equals("yes", StringComparison.OrdinalIgnoreCase))
            {
                return string.IsNullOrWhiteSpace(parts[1]) ? null : parts[1];
            }
        }

        return null;
    }

    public async Task ConnectAsync(string ssid, string? password, CancellationToken cancellationToken)
    {
        var args = password is null
            ? $"device wifi connect \"{Escape(ssid)}\""
            : $"device wifi connect \"{Escape(ssid)}\" password \"{Escape(password)}\"";
        try
        {
            await ShellRunner.RunOrThrowAsync("nmcli", args, cancellationToken);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("Not authorized to control networking", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "NetworkManager refused the connect: polkit requires a local+active session. " +
                "Over SSH on a headless host, drop a polkit override like:\n" +
                "  sudo tee /etc/polkit-1/rules.d/50-ecoplug.rules > /dev/null <<'EOF'\n" +
                "  polkit.addRule(function(action, subject) {\n" +
                "      if (action.id.indexOf(\"org.freedesktop.NetworkManager.\") == 0 && subject.user == \"" + Environment.UserName + "\") {\n" +
                "          return polkit.Result.YES;\n" +
                "      }\n" +
                "  });\n" +
                "  EOF",
                ex);
        }
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken)
    {
        var iface = await GetWifiInterfaceAsync(cancellationToken);
        if (iface is null)
        {
            return;
        }

        await ShellRunner.RunAsync("nmcli", $"device disconnect {iface}", cancellationToken);
    }

    public Task WaitForIPv4Async(string requiredPrefix, TimeSpan timeout, CancellationToken cancellationToken)
        => WifiController.WaitForAnyIPv4Async(requiredPrefix, timeout, cancellationToken);

    private static IReadOnlyList<WifiNetwork> ParseNmcliScan(string output)
    {
        var results = new List<WifiNetwork>();
        var seen = new HashSet<string>();
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var parts = SplitNmcli(line);
            if (parts.Length < 3)
            {
                continue;
            }

            var ssid = parts[0];
            if (string.IsNullOrWhiteSpace(ssid) || !seen.Add(ssid))
            {
                continue;
            }

            int? signal = int.TryParse(parts[1], out var parsed) ? parsed : null;
            var isOpen = string.IsNullOrWhiteSpace(parts[2]) || parts[2].Equals("--", StringComparison.Ordinal);
            results.Add(new WifiNetwork(ssid, signal, isOpen));
        }

        return results;
    }

    private static string[] SplitNmcli(string line)
    {
        var fields = new List<string>();
        var current = new System.Text.StringBuilder();
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '\\' && i + 1 < line.Length && line[i + 1] == ':')
            {
                current.Append(':');
                i++;
                continue;
            }

            if (c == ':')
            {
                fields.Add(current.ToString());
                current.Clear();
                continue;
            }

            current.Append(c);
        }

        fields.Add(current.ToString());
        return fields.ToArray();
    }

    private static async Task<string?> GetWifiInterfaceAsync(CancellationToken cancellationToken)
    {
        var (exit, stdout, _) = await ShellRunner.RunAsync("nmcli", "-t -f DEVICE,TYPE device", cancellationToken);
        if (exit != 0)
        {
            return null;
        }

        foreach (var line in stdout.Split('\n'))
        {
            var parts = SplitNmcli(line);
            if (parts.Length >= 2 && parts[1].Equals("wifi", StringComparison.OrdinalIgnoreCase))
            {
                return parts[0];
            }
        }

        return null;
    }

    private static string Escape(string value) => value.Replace("\"", "\\\"");
}
