using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

internal interface IWifiController
{
    Task<IReadOnlyList<WifiNetwork>> ScanAsync(CancellationToken cancellationToken);
    Task<string?> GetCurrentSsidAsync(CancellationToken cancellationToken);
    Task ConnectAsync(string ssid, string? password, CancellationToken cancellationToken);
    Task DisconnectAsync(CancellationToken cancellationToken);
    Task WaitForIPv4Async(string requiredPrefix, TimeSpan timeout, CancellationToken cancellationToken);
}

internal sealed record WifiNetwork(string Ssid, int? SignalPercent, bool IsOpen);

internal static class WifiController
{
    public static IWifiController Create()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return new WindowsWifiController();
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return new LinuxWifiController();
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return new MacWifiController();
        }

        throw new PlatformNotSupportedException("WiFi control requires Windows, Linux, or macOS.");
    }

    public static async Task WaitForAnyIPv4Async(string requiredPrefix, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (iface.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                foreach (var address in iface.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }

                    var text = address.Address.ToString();
                    if (text.StartsWith(requiredPrefix, StringComparison.Ordinal))
                    {
                        return;
                    }
                }
            }

            await Task.Delay(500, cancellationToken);
        }

        throw new TimeoutException($"Timed out waiting for IPv4 address with prefix {requiredPrefix}.");
    }
}

internal static class ShellRunner
{
    public static async Task<(int ExitCode, string Stdout, string Stderr)> RunAsync(
        string fileName,
        string arguments,
        CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start {fileName}.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return (process.ExitCode, await stdoutTask, await stderrTask);
    }

    public static async Task<string> RunOrThrowAsync(string fileName, string arguments, CancellationToken cancellationToken)
    {
        var (exit, stdout, stderr) = await RunAsync(fileName, arguments, cancellationToken);
        if (exit != 0)
        {
            var combined = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : stderr.Trim();
            throw new InvalidOperationException($"{fileName} {arguments} failed ({exit}): {combined}");
        }

        return stdout;
    }
}
