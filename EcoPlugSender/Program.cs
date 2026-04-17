using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Security.Cryptography;

return await App.RunAsync(args);

internal enum EcoPlugMode
{
    BuildAndSend,
    DecodeHex,
    Discover,
    PcapTimeline,
    Rename,
    Provision,
    FindPlugs,
    Configure,
}

internal static class App
{
    public static async Task<int> RunAsync(string[] args)
    {
        try
        {
            var options = EcoPlugOptions.Parse(args);
            if (options.ShowHelp)
            {
                PrintUsage();
                return 0;
            }

            if (options.Mode == EcoPlugMode.DecodeHex)
            {
                var packetToDecode = PacketHex.Parse(options.HexPacket!);
                Console.WriteLine(EcoPlugPacketDecoder.Describe(packetToDecode));
                return 0;
            }

            if (options.Mode == EcoPlugMode.PcapTimeline)
            {
                Console.WriteLine(PcapTimeline.Describe(options.PcapPath!, options.PcapPlugIp));
                return 0;
            }

            if (options.Mode == EcoPlugMode.Discover)
            {
                return await ExecuteDiscoverAsync(options);
            }

            if (options.Mode == EcoPlugMode.Provision)
            {
                return await ExecuteProvisionAsync(options);
            }

            if (options.Mode == EcoPlugMode.FindPlugs)
            {
                return await ExecuteFindPlugsAsync(options);
            }

            if (options.Mode == EcoPlugMode.Configure)
            {
                return await ExecuteConfigureAsync(options);
            }

            if (options.Mode == EcoPlugMode.Rename)
            {
                if (options.DryRun)
                {
                    var dryRunSteps = BuildRenameSteps(options);
                    var dryRunPackets = BuildTimedRenamePackets(dryRunSteps);
                    Console.WriteLine($"Built {dryRunPackets.Count}-packet rename session for {options.PlugId} ({options.CurrentName} -> {options.NewName}).");
                    Console.WriteLine("Rename also sends background broadcast traffic to 255.255.255.255:5888 and :25 while the direct UDP session runs.");
                    PrintRenamePackets(dryRunPackets, options.PrintPacket || options.DryRun, options.PrintDecode);
                    Console.WriteLine("Dry run only. Packets were not sent.");
                    return 0;
                }

                var steps = BuildRenameSteps(options);
                var packets = BuildTimedRenamePackets(steps);
                Console.WriteLine($"Built {packets.Count}-packet rename session for {options.PlugId} ({options.CurrentName} -> {options.NewName}).");
                Console.WriteLine("Rename also sends background broadcast traffic to 255.255.255.255:5888 and :25 while the direct UDP session runs.");

                var run = await ExecuteRenameAsync(options, steps);
                var responses = run.StepResults.SelectMany(result => result.Responses).ToList();
                Console.WriteLine($"Sent rename session to {options.IpAddress}:{options.Port}.");
                Console.WriteLine($"Received {responses.Count} UDP responses.");
                Console.WriteLine(run.Succeeded
                    ? $"Rename succeeded. Device now reports \"{run.ReportedName}\"."
                    : $"Rename did not stick. Device still reports \"{run.ReportedName ?? options.CurrentName}\".");

                if (options.PrintPacket || options.PrintDecode)
                {
                    PrintRenamePackets(packets, options.PrintPacket, options.PrintDecode);
                }

                if (options.PrintPacket)
                {
                    var responseIndex = 0;
                    foreach (var stepResult in run.StepResults)
                    {
                        foreach (var response in stepResult.Responses)
                        {
                            responseIndex++;
                            Console.WriteLine($"[{stepResult.Label} response {responseIndex} from {response.RemoteEndPoint}] {PacketHex.Format(response.Payload)}");
                        }
                    }
                }

                if (options.PrintDecode)
                {
                    var responseIndex = 0;
                    foreach (var stepResult in run.StepResults)
                    {
                        foreach (var response in stepResult.Responses)
                        {
                            responseIndex++;
                            Console.WriteLine();
                            Console.WriteLine($"[{stepResult.Label} response {responseIndex} from {response.RemoteEndPoint}]");
                            Console.WriteLine(EcoPlugPacketDecoder.Describe(response.Payload));
                        }
                    }
                }

                return 0;
            }

            var packet = EcoPlugPacketBuilder.BuildWritePacket(options.PlugId!, options.PlugName!, options.PowerState!.Value);
            var operationLabel = options.PowerState.Value.ToString().ToLowerInvariant();

            Console.WriteLine($"Built {packet.Length}-byte packet for {options.PlugId} ({operationLabel}).");

            if (options.PrintPacket || options.DryRun)
            {
                Console.WriteLine(PacketHex.Format(packet));
            }

            if (options.PrintDecode)
            {
                Console.WriteLine();
                Console.WriteLine(EcoPlugPacketDecoder.Describe(packet));
            }

            if (options.DryRun)
            {
                Console.WriteLine("Dry run only. Packet was not sent.");
                return 0;
            }

            await EcoPlugClient.SendAsync(options.IpAddress!, options.Port, packet);
            Console.WriteLine($"Sent UDP packet to {options.IpAddress}:{options.Port}.");
            return 0;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            Console.Error.WriteLine();
            PrintUsage();
            return 1;
        }
        catch (SocketException ex)
        {
            Console.Error.WriteLine($"UDP send failed: {ex.Message}");
            return 2;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  EcoPlugSender <on|off> [--ip <address>] [--port <port>] [--plug-id <id>] [--name <name>] [--dry-run] [--print-packet] [--decode]");
        Console.WriteLine("  EcoPlugSender rename --current-name <name> --new-name <name> [--ip <address>] [--port <port>] [--plug-id <id>] [--dry-run] [--print-packet] [--decode]");
        Console.WriteLine("  EcoPlugSender discover [--timeout-ms <ms>] [--decode]");
        Console.WriteLine("  EcoPlugSender provision --ssid <ssid> --password <pass> --zip <zip> [--name <name>] [--plug-id <id>] [--ip <address>] [--port <port>] [--dry-run] [--print-packet] [--decode]");
        Console.WriteLine("  EcoPlugSender find-plugs");
        Console.WriteLine("  EcoPlugSender configure --ssid <home-ssid> --password <home-pass> --zip <zip> [--plug-ap <ECO-XXXXXXXX>] [--name <name>]");
        Console.WriteLine("  EcoPlugSender decode --hex \"16 00 05 00 ...\"");
        Console.WriteLine("  EcoPlugSender pcap-timeline --pcap <file> [--plug-ip <address>]");
        Console.WriteLine();
        Console.WriteLine("Defaults:");
        Console.WriteLine("  --ip        192.168.68.126");
        Console.WriteLine("  --port      80");
        Console.WriteLine("  --plug-id   ECO-7806EDD6");
        Console.WriteLine("  --name      Heater");
        Console.WriteLine();
        Console.WriteLine("Extras:");
        Console.WriteLine("  --decode    Print a structured field breakdown for the built packet");
        Console.WriteLine("  --hex       Hex packet to decode in decode mode");
    }

    private static IReadOnlyList<RenameStep> BuildRenameSteps(EcoPlugOptions options)
    {
        var session = CreateRenameSession();
        var probe1 = EcoPlugPacketBuilder.BuildProbePacket(options.PlugId!, options.CurrentName!, session.SequenceSet.Probe1, AddTicks(session.BaseField116, 0), session.Field124);
        var probe2 = EcoPlugPacketBuilder.BuildProbePacket(options.PlugId!, options.CurrentName!, session.SequenceSet.Probe2, AddTicks(session.BaseField116, 5001), session.Field124);
        var probe3 = EcoPlugPacketBuilder.BuildProbePacket(options.PlugId!, options.CurrentName!, session.SequenceSet.Probe3, AddTicks(session.BaseField116, 10002), session.Field124);
        var rename = EcoPlugPacketBuilder.BuildRenamePacket(options.PlugId!, options.CurrentName!, options.NewName!, session.SequenceSet.Rename, AddTicks(session.BaseField116, 11322), session.Field124);
        var info = EcoPlugPacketBuilder.BuildInfoPacket(options.PlugId!, options.CurrentName!, session.SequenceSet.Info, AddTicks(session.BaseField116, 11342), session.Field124);
        var read = EcoPlugPacketBuilder.BuildReadPacket(options.PlugId!, options.CurrentName!, session.SequenceSet.Read, AddTicks(session.BaseField116, 11861), session.Field124);
        var commit = EcoPlugPacketBuilder.BuildCommitPacket(options.PlugId!, options.CurrentName!, session.SequenceSet.Commit, AddTicks(session.BaseField116, 11865), session.Field124);
        var verifyRead = EcoPlugPacketBuilder.BuildReadPacket(options.PlugId!, options.CurrentName!, session.SequenceSet.Verify, AddTicks(session.BaseField116, 23100), session.Field124);

        return new List<RenameStep>
        {
            new("probe1", probe1, 0, 2, 2, 250),
            new("probe2", probe2, 5001, 2, 2, 250),
            new("probe3", probe3, 10002, 2, 2, 250),
            new("rename", rename, 11322, 2, 1, 250),
            new("info", info, 11342, 2, 1, 250),
            new("read", read, 11861, 2, 1, 250),
            new("commit", commit, 11865, 2, 1, 250),
            new("verify", verifyRead, 23100, 2, 1, 1000),
        };
    }

    private static RenameSession CreateRenameSession()
    {
        return new RenameSession(
            unchecked((uint)Environment.TickCount64),
            GenerateRandomBytes(4),
            new RenameSequenceSet(
                GenerateSequenceBytes(),
                GenerateSequenceBytes(),
                GenerateSequenceBytes(),
                GenerateSequenceBytes(),
                GenerateSequenceBytes(),
                GenerateSequenceBytes(),
                GenerateSequenceBytes(),
                GenerateSequenceBytes()));
    }

    private static void PrintRenamePackets(IReadOnlyList<TimedPacket> packets, bool printPacket, bool printDecode)
    {
        if (printPacket)
        {
            foreach (var packet in packets)
            {
                Console.WriteLine($"[{packet.Label} @ +{packet.SendAfterMs}ms] {PacketHex.Format(packet.Payload)}");
            }
        }

        if (printDecode)
        {
            foreach (var packet in packets)
            {
                Console.WriteLine();
                Console.WriteLine($"[{packet.Label} @ +{packet.SendAfterMs}ms]");
                Console.WriteLine(EcoPlugPacketDecoder.Describe(packet.Payload));
            }
        }
    }

    private static IReadOnlyList<TimedPacket> BuildTimedRenamePackets(IReadOnlyList<RenameStep> steps)
    {
        var packets = new List<TimedPacket>();
        foreach (var step in steps)
        {
            for (var duplicateIndex = 0; duplicateIndex < step.DuplicateCount; duplicateIndex++)
            {
                var suffix = (char)('a' + duplicateIndex);
                packets.Add(new TimedPacket(
                    $"{step.Label}-{suffix}",
                    step.Payload,
                    step.StartAfterMs + (duplicateIndex * step.DuplicateGapMs)));
            }
        }

        return packets;
    }

    private static readonly System.Text.RegularExpressions.Regex PlugApPattern =
        new("^ECO-[0-9A-F]{8}$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static async Task<int> ExecuteFindPlugsAsync(EcoPlugOptions options)
    {
        var showAll = options.PrintPacket;
        var controller = WifiController.Create();
        Console.WriteLine("Scanning for nearby WiFi networks...");
        var networks = await controller.ScanAsync(CancellationToken.None);
        Console.WriteLine($"Scan returned {networks.Count} SSIDs.");

        if (showAll)
        {
            foreach (var net in networks.OrderByDescending(n => n.SignalPercent ?? -1))
            {
                var signal = net.SignalPercent is int s ? $"{s}%" : "?";
                var marker = PlugApPattern.IsMatch(net.Ssid) ? " [PLUG]" : string.Empty;
                Console.WriteLine($"  \"{net.Ssid}\"  signal={signal}  {(net.IsOpen ? "open" : "secured")}{marker}");
            }

            return 0;
        }

        var plugs = networks.Where(n => PlugApPattern.IsMatch(n.Ssid)).ToList();
        if (plugs.Count == 0)
        {
            Console.WriteLine("No ECO plug APs matched. Use --all to list every SSID the scan saw.");
            return 0;
        }

        Console.WriteLine($"Found {plugs.Count} plug AP{(plugs.Count == 1 ? "" : "s")}:");
        foreach (var plug in plugs)
        {
            var signal = plug.SignalPercent is int s ? $"{s}%" : "?";
            Console.WriteLine($"  {plug.Ssid}  signal={signal}  {(plug.IsOpen ? "open" : "secured")}");
        }

        return 0;
    }

    private static async Task<int> ExecuteConfigureAsync(EcoPlugOptions options)
    {
        var controller = WifiController.Create();
        var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));

        var originalSsid = await controller.GetCurrentSsidAsync(cts.Token);
        if (!string.IsNullOrEmpty(originalSsid))
        {
            Console.WriteLine($"Currently connected to \"{originalSsid}\".");
        }

        string plugAp;
        if (!string.IsNullOrWhiteSpace(options.PlugId))
        {
            plugAp = options.PlugId!;
            if (!PlugApPattern.IsMatch(plugAp))
            {
                throw new ArgumentException($"--plug-ap must match ECO-XXXXXXXX, got {plugAp}.");
            }
        }
        else
        {
            Console.WriteLine("Scanning for ECO plug APs...");
            var networks = await controller.ScanAsync(cts.Token);
            var candidates = networks.Where(n => PlugApPattern.IsMatch(n.Ssid)).ToList();
            if (candidates.Count == 0)
            {
                Console.Error.WriteLine("No ECO plug APs found. Factory-reset the plug and retry, or specify --plug-ap.");
                return 3;
            }

            if (candidates.Count > 1)
            {
                Console.Error.WriteLine($"Multiple ECO plug APs found ({string.Join(", ", candidates.Select(c => c.Ssid))}). Specify --plug-ap.");
                return 3;
            }

            plugAp = candidates[0].Ssid;
        }

        Console.WriteLine($"Connecting to plug AP \"{plugAp}\"...");
        await controller.ConnectAsync(plugAp, null, cts.Token);

        Console.WriteLine("Waiting for 192.168.4.x address...");
        await controller.WaitForIPv4Async("192.168.4.", TimeSpan.FromSeconds(30), cts.Token);

        Console.WriteLine("Sending provisioning packet...");
        var sequenceBytes = GenerateSequenceBytes();
        var field116 = GenerateRandomBytes(4);
        var field124 = GenerateRandomBytes(4);
        var packet = EcoPlugPacketBuilder.BuildProvisionPacket(
            plugAp,
            options.PlugName!,
            options.Ssid!,
            options.Password!,
            options.ZipCode!,
            sequenceBytes,
            field116,
            field124);

        await EcoPlugClient.SendAsync(System.Net.IPAddress.Parse("192.168.4.1"), 80, packet);
        Console.WriteLine($"Sent {packet.Length}-byte provision packet to 192.168.4.1:80.");

        if (options.PrintDecode)
        {
            Console.WriteLine();
            Console.WriteLine(EcoPlugPacketDecoder.Describe(packet));
        }

        if (!string.IsNullOrEmpty(originalSsid))
        {
            Console.WriteLine($"Reconnecting host to \"{originalSsid}\"...");
            try
            {
                await controller.ConnectAsync(originalSsid, null, cts.Token);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Automatic reconnect failed: {ex.Message}. You may need to reconnect manually.");
            }
        }
        else
        {
            Console.WriteLine("No prior SSID recorded; leaving WiFi state as-is.");
        }

        Console.WriteLine("Waiting briefly for plug to join home network, then running discover...");
        await Task.Delay(TimeSpan.FromSeconds(15), cts.Token);

        var discoverOptions = new EcoPlugOptions(
            EcoPlugMode.Discover, null, null, 80, null, null, null, null,
            false, false, false, null, false, null, null, 10000);
        return await ExecuteDiscoverAsync(discoverOptions);
    }

    private static async Task<int> ExecuteProvisionAsync(EcoPlugOptions options)
    {
        var sequenceBytes = GenerateSequenceBytes();
        var field116 = GenerateRandomBytes(4);
        var field124 = GenerateRandomBytes(4);

        var packet = EcoPlugPacketBuilder.BuildProvisionPacket(
            options.PlugId!,
            options.PlugName!,
            options.Ssid!,
            options.Password!,
            options.ZipCode!,
            sequenceBytes,
            field116,
            field124);

        Console.WriteLine($"Built {packet.Length}-byte provision packet for {options.PlugId} (ssid=\"{options.Ssid}\", zip={options.ZipCode}).");

        if (options.PrintPacket || options.DryRun)
        {
            Console.WriteLine(PacketHex.Format(packet));
        }

        if (options.PrintDecode)
        {
            Console.WriteLine();
            Console.WriteLine(EcoPlugPacketDecoder.Describe(packet));
        }

        if (options.DryRun)
        {
            Console.WriteLine("Dry run only. Packet was not sent.");
            return 0;
        }

        await EcoPlugClient.SendAsync(options.IpAddress!, options.Port, packet);
        Console.WriteLine($"Sent UDP packet to {options.IpAddress}:{options.Port}.");
        return 0;
    }

    private static async Task<int> ExecuteDiscoverAsync(EcoPlugOptions options)
    {
        Console.WriteLine($"Discover listens on UDP 8900 and sends connect-broadcast packets to 255.255.255.255:5888 and :25 for {options.DiscoverDurationMs}ms.");

        using var client = EcoPlugClient.OpenClient(sourcePort: 8900, enableBroadcast: true);
        using var cts = new CancellationTokenSource(options.DiscoverDurationMs);

        var broadcastTask = RunConnectingBroadcastLoopAsync(client, cts.Token);
        var responses = new List<EcoPlugResponse>();

        try
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var result = await client.ReceiveAsync(cts.Token);
                    responses.Add(new EcoPlugResponse(result.Buffer, result.RemoteEndPoint));
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
        finally
        {
            await IgnoreCanceledTaskAsync(broadcastTask);
        }

        Console.WriteLine($"Received {responses.Count} UDP responses.");

        var plugs = new Dictionary<(IPAddress Address, string PlugId), DiscoveredPlug>();
        var nonEcoEndpoints = new HashSet<IPEndPoint>();

        foreach (var response in responses)
        {
            var info = TryExtractEcoInfo(response.Payload);
            if (info is null)
            {
                nonEcoEndpoints.Add(response.RemoteEndPoint);
                continue;
            }

            var key = (response.RemoteEndPoint.Address, info.Value.PlugId);
            if (plugs.TryGetValue(key, out var existing))
            {
                plugs[key] = existing with
                {
                    Name = existing.Name ?? info.Value.Name,
                    PacketCount = existing.PacketCount + 1,
                };
            }
            else
            {
                plugs[key] = new DiscoveredPlug(response.RemoteEndPoint, info.Value.PlugId, info.Value.Name, 1);
            }
        }

        if (plugs.Count == 0)
        {
            Console.WriteLine("No ECO plug replies were observed.");
        }
        else
        {
            foreach (var plug in plugs.Values)
            {
                var nameText = string.IsNullOrWhiteSpace(plug.Name) ? "<unknown>" : plug.Name;
                Console.WriteLine($"Discovered {plug.RemoteEndPoint.Address}:{plug.RemoteEndPoint.Port} {plug.PlugId} \"{nameText}\" via {plug.PacketCount} packets.");
            }
        }

        if (nonEcoEndpoints.Count > 0)
        {
            var endpointList = string.Join(", ", nonEcoEndpoints.Select(ep => ep.ToString()));
            Console.WriteLine($"Also received non-ECO UDP responses from: {endpointList}");
        }

        if (options.PrintDecode)
        {
            var index = 0;
            foreach (var response in responses)
            {
                index++;
                Console.WriteLine();
                Console.WriteLine($"[discover response {index} from {response.RemoteEndPoint}]");
                if (EcoPlugPacketInspector.LooksLikeEcoPacket(response.Payload)
                    || EcoPlugPacketDecoder.LooksLikeResponse(response.Payload))
                {
                    Console.WriteLine(EcoPlugPacketDecoder.Describe(response.Payload));
                }
                else
                {
                    Console.WriteLine("Unrecognized UDP payload");
                    Console.WriteLine(PacketHex.Format(response.Payload));
                }
            }
        }

        return 0;
    }

    private static (string PlugId, string? Name)? TryExtractEcoInfo(byte[] packet)
    {
        var scanEnd = Math.Min(packet.Length - 16, 64);
        for (var i = 0; i <= scanEnd; i++)
        {
            if (packet[i] == 0x45 && packet[i + 1] == 0x43 && packet[i + 2] == 0x4F && packet[i + 3] == 0x2D)
            {
                var plugId = System.Text.Encoding.ASCII.GetString(packet, i, 16).TrimEnd('\0');
                if (string.IsNullOrWhiteSpace(plugId) || !plugId.StartsWith("ECO-"))
                {
                    continue;
                }

                string? name = null;
                if (packet.Length >= i + 32 + 32)
                {
                    name = System.Text.Encoding.ASCII.GetString(packet, i + 32, 32).TrimEnd('\0');
                    if (string.IsNullOrWhiteSpace(name))
                    {
                        name = null;
                    }
                }

                return (plugId, name);
            }
        }

        return null;
    }

    private static async Task<RenameRun> ExecuteRenameAsync(EcoPlugOptions options, IReadOnlyList<RenameStep> steps)
    {
        using var directClient = EcoPlugClient.OpenClient();
        using var broadcastClient = EcoPlugClient.OpenClient(sourcePort: 8900, enableBroadcast: true);

        var remoteEndpoint = new IPEndPoint(options.IpAddress!, options.Port);
        using var broadcastCancellation = new CancellationTokenSource();
        var broadcastTask = RunConnectingBroadcastLoopAsync(broadcastClient, broadcastCancellation.Token);

        try
        {
            var stepResults = new List<RenameStepResult>();
            var stopwatch = Stopwatch.StartNew();

            foreach (var step in steps.OrderBy(step => step.StartAfterMs))
            {
                var waitMs = step.StartAfterMs - (int)stopwatch.ElapsedMilliseconds;
                if (waitMs > 0)
                {
                    await Task.Delay(waitMs);
                }

                var responses = await EcoPlugClient.SendAndReceiveAsync(
                    directClient,
                    remoteEndpoint,
                    step.Payload,
                    step.DuplicateCount,
                    step.DuplicateGapMs,
                    step.ResponseIdleTimeoutMs);

                stepResults.Add(new RenameStepResult(step.Label, step.Payload, responses));
            }

            broadcastCancellation.Cancel();
            await IgnoreCanceledTaskAsync(broadcastTask);
            return SummarizeRename(options.NewName!, options.CurrentName!, stepResults);
        }
        finally
        {
            if (!broadcastCancellation.IsCancellationRequested)
            {
                broadcastCancellation.Cancel();
            }

            await IgnoreCanceledTaskAsync(broadcastTask);
        }
    }

    private static RenameRun SummarizeRename(string targetName, string fallbackName, IReadOnlyList<RenameStepResult> stepResults)
    {
        var responseFields = stepResults
            .SelectMany(result => result.Responses.Select(response => EcoPlugPacketInspector.Inspect(response.Payload)))
            .ToList();

        var reportedName = responseFields
            .Select(fields => fields.PlugName)
            .LastOrDefault(name => !string.IsNullOrWhiteSpace(name))
            ?? fallbackName;

        var renameAcknowledged = responseFields.Any(fields =>
            fields.CommandCode == 0x13 &&
            string.Equals(fields.PlugName, targetName, StringComparison.Ordinal));
        var finalReadsConfirmed = responseFields.Any(fields =>
            fields.CommandCode is 0x05 or 0x17 or 0x23 &&
            string.Equals(fields.PlugName, targetName, StringComparison.Ordinal));

        return new RenameRun(stepResults, renameAcknowledged && finalReadsConfirmed, reportedName);
    }

    private static async Task RunConnectingBroadcastLoopAsync(UdpClient client, CancellationToken cancellationToken)
    {
        var broadcast5888 = new IPEndPoint(IPAddress.Broadcast, 5888);
        var broadcast25 = new IPEndPoint(IPAddress.Broadcast, 25);

        while (!cancellationToken.IsCancellationRequested)
        {
            await SendBroadcastBurstAsync(client, broadcast5888, 4, cancellationToken);
            await SendBroadcastBurstAsync(client, broadcast25, 3, cancellationToken);
            await SendBroadcastBurstAsync(client, broadcast5888, 3, cancellationToken);
            await SendBroadcastBurstAsync(client, broadcast25, 3, cancellationToken);
            await Task.Delay(250, cancellationToken);
        }
    }

    private static async Task SendBroadcastBurstAsync(UdpClient client, IPEndPoint endpoint, int count, CancellationToken cancellationToken)
    {
        for (var i = 0; i < count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var counter = unchecked((uint)(Environment.TickCount64 / 1000));
            var payload = EcoPlugPacketBuilder.BuildConnectingBroadcastPacket(counter);
            await EcoPlugClient.SendToAsync(client, endpoint, payload);
            await Task.Delay(40, cancellationToken);
        }
    }

    private static async Task IgnoreCanceledTaskAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static byte[] AddTicks(uint baseTicks, uint delta)
    {
        return BitConverter.GetBytes(unchecked(baseTicks + delta));
    }

    private static byte[] GenerateRandomBytes(int length)
    {
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    private static byte[] GenerateSequenceBytes()
    {
        var sequenceValue = RandomNumberGenerator.GetInt32(0x10000);
        return [(byte)0x00, (byte)0x00, (byte)(sequenceValue >> 8), (byte)sequenceValue];
    }

}

internal sealed record DiscoveredPlug(IPEndPoint RemoteEndPoint, string PlugId, string? Name, int PacketCount);

internal sealed record TimedPacket(string Label, byte[] Payload, int SendAfterMs);

internal sealed record RenameStep(
    string Label,
    byte[] Payload,
    int StartAfterMs,
    int DuplicateCount,
    int DuplicateGapMs,
    int ResponseIdleTimeoutMs);

internal sealed record RenameStepResult(
    string Label,
    byte[] Payload,
    IReadOnlyList<EcoPlugResponse> Responses);

internal sealed record RenameRun(
    IReadOnlyList<RenameStepResult> StepResults,
    bool Succeeded,
    string ReportedName);

internal sealed record RenameSession(
    uint BaseField116,
    byte[] Field124,
    RenameSequenceSet SequenceSet);

internal sealed record RenameSequenceSet(
    byte[] Probe1,
    byte[] Probe2,
    byte[] Probe3,
    byte[] Rename,
    byte[] Info,
    byte[] Read,
    byte[] Commit,
    byte[] Verify);

internal sealed record EcoPlugOptions(
    EcoPlugMode Mode,
    PlugPowerState? PowerState,
    IPAddress? IpAddress,
    int Port,
    string? PlugId,
    string? PlugName,
    string? CurrentName,
    string? NewName,
    bool DryRun,
    bool PrintPacket,
    bool PrintDecode,
    string? HexPacket,
    bool ShowHelp,
    string? PcapPath = null,
    IPAddress? PcapPlugIp = null,
    int DiscoverDurationMs = 5000,
    string? Ssid = null,
    string? Password = null,
    string? ZipCode = null)
{
    private const string DefaultIp = "192.168.68.126";
    private const string DefaultProvisionIp = "192.168.4.1";
    private const int DefaultPort = 80;
    private const string DefaultPlugId = "ECO-7806EDD6";
    private const string DefaultPlugName = "Heater";
    internal const int DefaultDiscoverDurationMs = 5000;

    public static EcoPlugOptions Parse(string[] args)
    {
        if (args.Length == 0)
        {
            throw new ArgumentException("Missing command.");
        }

        if (args.Length == 1 && args[0] is "-h" or "--help")
        {
            return new EcoPlugOptions(EcoPlugMode.BuildAndSend, null, null, DefaultPort, null, null, null, null, false, false, false, null, true);
        }

        return args[0].Equals("decode", StringComparison.OrdinalIgnoreCase)
            ? ParseDecodeMode(args[1..])
            : args[0].Equals("pcap-timeline", StringComparison.OrdinalIgnoreCase)
                ? ParsePcapTimelineMode(args[1..])
            : args[0].Equals("rename", StringComparison.OrdinalIgnoreCase)
                ? ParseRenameMode(args[1..])
            : args[0].Equals("discover", StringComparison.OrdinalIgnoreCase)
                ? ParseDiscoverMode(args[1..])
            : args[0].Equals("provision", StringComparison.OrdinalIgnoreCase)
                ? ParseProvisionMode(args[1..])
            : args[0].Equals("find-plugs", StringComparison.OrdinalIgnoreCase)
                ? ParseFindPlugsMode(args[1..])
            : args[0].Equals("configure", StringComparison.OrdinalIgnoreCase)
                ? ParseConfigureMode(args[1..])
            : ParseBuildMode(args);
    }

    private static EcoPlugOptions ParseFindPlugsMode(string[] args)
    {
        var showAll = false;
        foreach (var arg in args)
        {
            if (arg is "-h" or "--help")
            {
                return new EcoPlugOptions(EcoPlugMode.FindPlugs, null, null, DefaultPort, null, null, null, null, false, false, false, null, true);
            }

            if (arg == "--all")
            {
                showAll = true;
                continue;
            }

            throw new ArgumentException($"Unknown option: {arg}");
        }

        return new EcoPlugOptions(EcoPlugMode.FindPlugs, null, null, DefaultPort, null, null, null, null, false, showAll, false, null, false);
    }

    private static EcoPlugOptions ParseConfigureMode(string[] args)
    {
        string? ssid = null;
        string? password = null;
        string? zipCode = null;
        string? plugAp = null;
        var plugName = DefaultPlugName;
        var printDecode = false;
        var showHelp = false;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg is "-h" or "--help")
            {
                showHelp = true;
                continue;
            }

            if (arg == "--decode")
            {
                printDecode = true;
                continue;
            }

            if (!arg.StartsWith("-", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument in configure mode: {arg}");
            }

            var value = ReadOptionValue(args, ref i, arg);
            switch (arg)
            {
                case "--ssid":
                    ssid = value;
                    break;
                case "--password":
                    password = value;
                    break;
                case "--zip":
                    zipCode = value;
                    break;
                case "--plug-ap":
                    plugAp = value;
                    break;
                case "--name":
                    plugName = value;
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {arg}");
            }
        }

        if (showHelp)
        {
            return new EcoPlugOptions(EcoPlugMode.Configure, null, null, DefaultPort, null, null, null, null, false, false, false, null, true);
        }

        if (string.IsNullOrWhiteSpace(ssid))
        {
            throw new ArgumentException("Configure requires --ssid.");
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Configure requires --password.");
        }

        if (string.IsNullOrWhiteSpace(zipCode))
        {
            throw new ArgumentException("Configure requires --zip.");
        }

        return new EcoPlugOptions(
            EcoPlugMode.Configure,
            null,
            null,
            DefaultPort,
            plugAp,
            plugName,
            null,
            null,
            false,
            false,
            printDecode,
            null,
            false,
            null,
            null,
            DefaultDiscoverDurationMs,
            ssid,
            password,
            zipCode);
    }

    private static EcoPlugOptions ParseProvisionMode(string[] args)
    {
        var ipText = DefaultProvisionIp;
        var port = DefaultPort;
        var plugId = DefaultPlugId;
        var plugName = DefaultPlugName;
        string? ssid = null;
        string? password = null;
        string? zipCode = null;
        var dryRun = false;
        var printPacket = false;
        var printDecode = false;
        var showHelp = false;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg is "-h" or "--help")
            {
                showHelp = true;
                continue;
            }

            if (arg == "--dry-run")
            {
                dryRun = true;
                continue;
            }

            if (arg == "--print-packet")
            {
                printPacket = true;
                continue;
            }

            if (arg == "--decode")
            {
                printDecode = true;
                continue;
            }

            if (!arg.StartsWith("-", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument in provision mode: {arg}");
            }

            var value = ReadOptionValue(args, ref i, arg);
            switch (arg)
            {
                case "--ip":
                    ipText = value;
                    break;
                case "--port":
                    if (!int.TryParse(value, out port) || port is < 1 or > 65535)
                    {
                        throw new ArgumentException("Port must be a number between 1 and 65535.");
                    }
                    break;
                case "--plug-id":
                    plugId = value;
                    break;
                case "--name":
                    plugName = value;
                    break;
                case "--ssid":
                    ssid = value;
                    break;
                case "--password":
                    password = value;
                    break;
                case "--zip":
                    zipCode = value;
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {arg}");
            }
        }

        if (showHelp)
        {
            return new EcoPlugOptions(EcoPlugMode.Provision, null, null, DefaultPort, null, null, null, null, false, false, false, null, true);
        }

        if (string.IsNullOrWhiteSpace(ssid))
        {
            throw new ArgumentException("Provision requires --ssid.");
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Provision requires --password.");
        }

        if (string.IsNullOrWhiteSpace(zipCode))
        {
            throw new ArgumentException("Provision requires --zip.");
        }

        if (!IPAddress.TryParse(ipText, out var ipAddress))
        {
            throw new ArgumentException($"Invalid IP address: {ipText}");
        }

        return new EcoPlugOptions(
            EcoPlugMode.Provision,
            null,
            ipAddress,
            port,
            plugId,
            plugName,
            null,
            null,
            dryRun,
            printPacket,
            printDecode,
            null,
            false,
            null,
            null,
            DefaultDiscoverDurationMs,
            ssid,
            password,
            zipCode);
    }

    private static EcoPlugOptions ParseBuildMode(string[] args)
    {
        string? stateToken = null;
        var ipText = DefaultIp;
        var port = DefaultPort;
        var plugId = DefaultPlugId;
        var plugName = DefaultPlugName;
        var dryRun = false;
        var printPacket = false;
        var printDecode = false;
        var showHelp = false;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg is "-h" or "--help")
            {
                showHelp = true;
                continue;
            }

            if (arg == "--dry-run")
            {
                dryRun = true;
                continue;
            }

            if (arg == "--print-packet")
            {
                printPacket = true;
                continue;
            }

            if (arg == "--decode")
            {
                printDecode = true;
                continue;
            }

            if (!arg.StartsWith("-", StringComparison.Ordinal))
            {
                if (stateToken is null)
                {
                    stateToken = arg;
                    continue;
                }

                throw new ArgumentException($"Unexpected argument: {arg}");
            }

            var value = ReadOptionValue(args, ref i, arg);
            switch (arg)
            {
                case "--ip":
                    ipText = value;
                    break;
                case "--port":
                    if (!int.TryParse(value, out port) || port is < 1 or > 65535)
                    {
                        throw new ArgumentException("Port must be a number between 1 and 65535.");
                    }
                    break;
                case "--plug-id":
                    plugId = value;
                    break;
                case "--name":
                    plugName = value;
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {arg}");
            }
        }

        if (showHelp)
        {
            return new EcoPlugOptions(EcoPlugMode.BuildAndSend, null, null, DefaultPort, null, null, null, null, false, false, false, null, true);
        }

        if (stateToken is null)
        {
            throw new ArgumentException("Missing power state.");
        }

        if (!IPAddress.TryParse(ipText, out var ipAddress))
        {
            throw new ArgumentException($"Invalid IP address: {ipText}");
        }

        var state = stateToken.ToLowerInvariant() switch
        {
            "on" => PlugPowerState.On,
            "off" => PlugPowerState.Off,
            _ => throw new ArgumentException("Power state must be 'on' or 'off'."),
        };

        return new EcoPlugOptions(EcoPlugMode.BuildAndSend, state, ipAddress, port, plugId, plugName, null, null, dryRun, printPacket, printDecode, null, false);
    }

    private static EcoPlugOptions ParseRenameMode(string[] args)
    {
        var ipText = DefaultIp;
        var port = DefaultPort;
        var plugId = DefaultPlugId;
        string? currentName = null;
        string? newName = null;
        var dryRun = false;
        var printPacket = false;
        var printDecode = false;
        var showHelp = false;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg is "-h" or "--help")
            {
                showHelp = true;
                continue;
            }

            if (arg == "--dry-run")
            {
                dryRun = true;
                continue;
            }

            if (arg == "--print-packet")
            {
                printPacket = true;
                continue;
            }

            if (arg == "--decode")
            {
                printDecode = true;
                continue;
            }

            if (!arg.StartsWith("-", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument in rename mode: {arg}");
            }

            var value = ReadOptionValue(args, ref i, arg);
            switch (arg)
            {
                case "--ip":
                    ipText = value;
                    break;
                case "--port":
                    if (!int.TryParse(value, out port) || port is < 1 or > 65535)
                    {
                        throw new ArgumentException("Port must be a number between 1 and 65535.");
                    }
                    break;
                case "--plug-id":
                    plugId = value;
                    break;
                case "--current-name":
                    currentName = value;
                    break;
                case "--new-name":
                    newName = value;
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {arg}");
            }
        }

        if (showHelp)
        {
            return new EcoPlugOptions(EcoPlugMode.Rename, null, null, DefaultPort, null, null, null, null, false, false, false, null, true);
        }

        if (string.IsNullOrWhiteSpace(currentName))
        {
            throw new ArgumentException("Rename requires --current-name.");
        }

        if (string.IsNullOrWhiteSpace(newName))
        {
            throw new ArgumentException("Rename requires --new-name.");
        }

        if (!IPAddress.TryParse(ipText, out var ipAddress))
        {
            throw new ArgumentException($"Invalid IP address: {ipText}");
        }

        return new EcoPlugOptions(
            EcoPlugMode.Rename,
            null,
            ipAddress,
            port,
            plugId,
            null,
            currentName,
            newName,
            dryRun,
            printPacket,
            printDecode,
            null,
            false);
    }

    private static EcoPlugOptions ParseDecodeMode(string[] args)
    {
        var showHelp = false;
        string? hexPacket = null;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg is "-h" or "--help")
            {
                showHelp = true;
                continue;
            }

            if (!arg.StartsWith("-", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument in decode mode: {arg}");
            }

            var value = ReadOptionValue(args, ref i, arg);
            switch (arg)
            {
                case "--hex":
                    hexPacket = value;
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {arg}");
            }
        }

        if (showHelp)
        {
            return new EcoPlugOptions(EcoPlugMode.DecodeHex, null, null, DefaultPort, null, null, null, null, false, false, false, null, true);
        }

        if (string.IsNullOrWhiteSpace(hexPacket))
        {
            throw new ArgumentException("Decode mode requires --hex.");
        }

        return new EcoPlugOptions(EcoPlugMode.DecodeHex, null, null, DefaultPort, null, null, null, null, false, false, false, hexPacket, false);
    }

    private static EcoPlugOptions ParseDiscoverMode(string[] args)
    {
        var showHelp = false;
        var printDecode = false;
        var durationMs = DefaultDiscoverDurationMs;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg is "-h" or "--help")
            {
                showHelp = true;
                continue;
            }

            if (arg == "--decode")
            {
                printDecode = true;
                continue;
            }

            if (!arg.StartsWith("-", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument in discover mode: {arg}");
            }

            var value = ReadOptionValue(args, ref i, arg);
            switch (arg)
            {
                case "--timeout-ms":
                    if (!int.TryParse(value, out durationMs) || durationMs < 100)
                    {
                        throw new ArgumentException("--timeout-ms must be an integer >= 100.");
                    }
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {arg}");
            }
        }

        if (showHelp)
        {
            return new EcoPlugOptions(EcoPlugMode.Discover, null, null, DefaultPort, null, null, null, null, false, false, false, null, true);
        }

        return new EcoPlugOptions(
            EcoPlugMode.Discover,
            null,
            null,
            DefaultPort,
            null,
            null,
            null,
            null,
            false,
            false,
            printDecode,
            null,
            false,
            null,
            null,
            durationMs);
    }

    private static EcoPlugOptions ParsePcapTimelineMode(string[] args)
    {
        var showHelp = false;
        string? pcapPath = null;
        IPAddress? plugIp = null;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg is "-h" or "--help")
            {
                showHelp = true;
                continue;
            }

            if (!arg.StartsWith("-", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument in pcap-timeline mode: {arg}");
            }

            var value = ReadOptionValue(args, ref i, arg);
            switch (arg)
            {
                case "--pcap":
                    pcapPath = value;
                    break;
                case "--plug-ip":
                    if (!IPAddress.TryParse(value, out plugIp))
                    {
                        throw new ArgumentException($"Invalid plug IP address: {value}");
                    }
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {arg}");
            }
        }

        if (showHelp)
        {
            return new EcoPlugOptions(EcoPlugMode.PcapTimeline, null, null, DefaultPort, null, null, null, null, false, false, false, null, true);
        }

        if (string.IsNullOrWhiteSpace(pcapPath))
        {
            throw new ArgumentException("Pcap-timeline mode requires --pcap.");
        }

        return new EcoPlugOptions(EcoPlugMode.PcapTimeline, null, null, DefaultPort, null, null, null, null, false, false, false, null, false, pcapPath, plugIp);
    }

    private static string ReadOptionValue(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"Missing value for {option}.");
        }

        index++;
        return args[index];
    }

}
