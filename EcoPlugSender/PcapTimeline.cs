using System.Buffers.Binary;
using System.Net;
using System.Text;

internal static class PcapTimeline
{
    private const uint LinkTypeEthernet = 1;
    private const uint LinkTypeRawIp = 101;

    public static string Describe(string pcapPath, IPAddress? plugIp)
    {
        var entries = ReadTimelineEntries(pcapPath, plugIp).ToList();
        if (entries.Count == 0)
        {
            return $"No matching packets found in {pcapPath}.";
        }

        var lines = new List<string>
        {
            $"Timeline for {pcapPath}",
            plugIp is null
                ? "Showing UDP/TCP packets from the capture."
                : $"Showing packets involving {plugIp}, broadcasts, and DNS traffic.",
            $"Entries: {entries.Count}",
            string.Empty,
        };

        lines.AddRange(entries.Select(entry => entry.ToDisplayLine()));
        return string.Join(Environment.NewLine, lines);
    }

    private static IEnumerable<PcapTimelineEntry> ReadTimelineEntries(string pcapPath, IPAddress? plugIp)
    {
        using var stream = File.OpenRead(pcapPath);
        using var reader = new BinaryReader(stream);

        var globalHeader = reader.ReadBytes(24);
        if (globalHeader.Length < 24)
        {
            throw new ArgumentException($"PCAP file is too short: {pcapPath}");
        }

        var byteOrder = ParseByteOrder(globalHeader[..4]);
        var linkType = ReadUInt32(globalHeader, 20, byteOrder);
        var captureStart = default(DateTimeOffset?);

        while (reader.BaseStream.Position < reader.BaseStream.Length)
        {
            var packetHeader = reader.ReadBytes(16);
            if (packetHeader.Length == 0)
            {
                yield break;
            }

            if (packetHeader.Length < 16)
            {
                yield break;
            }

            var seconds = ReadUInt32(packetHeader, 0, byteOrder);
            var microseconds = ReadUInt32(packetHeader, 4, byteOrder);
            var includedLength = ReadUInt32(packetHeader, 8, byteOrder);

            var packetBytes = reader.ReadBytes((int)includedLength);
            if (packetBytes.Length < includedLength)
            {
                yield break;
            }

            if (!TryParseIpPacket(packetBytes, linkType, out var parsedPacket))
            {
                continue;
            }

            if (!IsInteresting(parsedPacket, plugIp))
            {
                continue;
            }

            var timestamp = DateTimeOffset.FromUnixTimeSeconds(seconds).AddTicks(microseconds * 10);
            captureStart ??= timestamp;
            var offset = timestamp - captureStart.Value;
            yield return BuildTimelineEntry(offset, parsedPacket);
        }
    }

    private static PcapTimelineEntry BuildTimelineEntry(TimeSpan offset, ParsedPacket packet)
    {
        var summary = $"{packet.Protocol} {FormatEndpoint(packet.SourceAddress, packet.SourcePort)} -> {FormatEndpoint(packet.DestinationAddress, packet.DestinationPort)} len={packet.Payload.Length}";

        if (packet.Protocol == "UDP" && TryDescribeEcoPacket(packet.Payload, out var ecoSummary))
        {
            summary = $"{summary} {ecoSummary}";
        }
        else if (packet.Protocol == "UDP" && TryDescribeConnectingBroadcast(packet, out var broadcastSummary))
        {
            summary = $"{summary} {broadcastSummary}";
        }
        else if (packet.Protocol == "UDP" && TryDescribeDns(packet, out var dnsSummary))
        {
            summary = $"{summary} {dnsSummary}";
        }

        return new PcapTimelineEntry(offset, summary);
    }

    private static bool TryDescribeEcoPacket(byte[] payload, out string summary)
    {
        summary = string.Empty;
        if (!EcoPlugPacketInspector.LooksLikeEcoPacket(payload))
        {
            return false;
        }

        var fields = EcoPlugPacketInspector.Inspect(payload);
        var parts = new List<string>
        {
            $"eco cmd=0x{fields.CommandCode:X2}",
            $"seq={ToCompactHex(fields.SequenceBytes)}",
        };

        if (!string.IsNullOrWhiteSpace(fields.PlugName))
        {
            parts.Add($"name=\"{fields.PlugName}\"");
        }

        if (!string.IsNullOrWhiteSpace(fields.RenameTargetName))
        {
            parts.Add($"new=\"{fields.RenameTargetName}\"");
        }

        if (fields.UnknownReadbackBytes.Any(b => b != 0x00))
        {
            parts.Add($"token={ToCompactHex(fields.UnknownReadbackBytes)}");
        }

        parts.Add($"f116={ToCompactHex(fields.Field116Bytes)}");
        parts.Add($"f124={ToCompactHex(fields.Field124Bytes)}");

        if (fields.CommandCode is 0x16 or 0x17 or 0x23 && fields.TailBytes.Length > 0)
        {
            parts.Add($"tail={ToCompactHex(fields.TailBytes)}");
        }

        summary = string.Join(' ', parts);
        return true;
    }

    private static bool TryDescribeConnectingBroadcast(ParsedPacket packet, out string summary)
    {
        summary = string.Empty;
        if (packet.Protocol != "UDP" ||
            !IPAddress.Broadcast.Equals(packet.DestinationAddress) ||
            packet.Payload.Length != 128 ||
            packet.SourcePort != 8900 ||
            packet.Payload.Take(24).Any(b => b != 0x00))
        {
            return false;
        }

        var marker = packet.Payload[24..28];
        var counter = packet.Payload[28..32];
        summary = $"connect-broadcast marker={ToCompactHex(marker)} counter={ToCompactHex(counter)}";
        return true;
    }

    private static bool TryDescribeDns(ParsedPacket packet, out string summary)
    {
        summary = string.Empty;
        if (packet.Protocol != "UDP" || packet.SourcePort != 53 && packet.DestinationPort != 53 || packet.Payload.Length < 12)
        {
            return false;
        }

        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(packet.Payload.AsSpan(4, 2));
        if (questionCount == 0)
        {
            return false;
        }

        if (!TryReadDnsQuestion(packet.Payload, 12, out var name))
        {
            return false;
        }

        summary = $"dns q=\"{name}\"";
        return true;
    }

    private static bool TryReadDnsQuestion(byte[] payload, int offset, out string name)
    {
        name = string.Empty;
        var labels = new List<string>();
        var position = offset;

        while (position < payload.Length)
        {
            var length = payload[position++];
            if (length == 0)
            {
                name = string.Join('.', labels);
                return true;
            }

            if (length >= 0xC0 || position + length > payload.Length)
            {
                return false;
            }

            labels.Add(Encoding.ASCII.GetString(payload, position, length));
            position += length;
        }

        return false;
    }

    private static bool IsInteresting(ParsedPacket packet, IPAddress? plugIp)
    {
        if (packet.Protocol is not ("UDP" or "TCP"))
        {
            return false;
        }

        if (plugIp is null)
        {
            return true;
        }

        return packet.SourceAddress.Equals(plugIp) ||
               packet.DestinationAddress.Equals(plugIp) ||
               IPAddress.Broadcast.Equals(packet.DestinationAddress) ||
               packet.DestinationAddress.ToString() == "224.0.0.251" ||
               packet.SourcePort == 53 ||
               packet.DestinationPort == 53;
    }

    private static bool TryParseIpPacket(byte[] packetBytes, uint linkType, out ParsedPacket parsedPacket)
    {
        parsedPacket = null!;
        ReadOnlySpan<byte> ipPacket = linkType switch
        {
            LinkTypeRawIp => packetBytes,
            LinkTypeEthernet => TryStripEthernet(packetBytes, out var stripped) ? stripped : default,
            _ => default,
        };

        if (ipPacket.IsEmpty || ipPacket.Length < 20 || ipPacket[0] >> 4 != 4)
        {
            return false;
        }

        var internetHeaderLength = (ipPacket[0] & 0x0F) * 4;
        if (internetHeaderLength < 20 || ipPacket.Length < internetHeaderLength + 8)
        {
            return false;
        }

        var protocol = ipPacket[9] switch
        {
            6 => "TCP",
            17 => "UDP",
            _ => string.Empty,
        };

        if (string.IsNullOrEmpty(protocol))
        {
            return false;
        }

        var sourceAddress = new IPAddress(ipPacket.Slice(12, 4));
        var destinationAddress = new IPAddress(ipPacket.Slice(16, 4));
        var transport = ipPacket[internetHeaderLength..];
        var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(transport[..2]);
        var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(2, 2));

        byte[] payload;
        if (protocol == "UDP")
        {
            var udpLength = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(4, 2));
            if (udpLength < 8 || transport.Length < udpLength)
            {
                return false;
            }

            payload = transport.Slice(8, udpLength - 8).ToArray();
        }
        else
        {
            var tcpHeaderLength = ((transport[12] >> 4) & 0x0F) * 4;
            if (tcpHeaderLength < 20 || transport.Length < tcpHeaderLength)
            {
                return false;
            }

            payload = transport[tcpHeaderLength..].ToArray();
        }

        parsedPacket = new ParsedPacket(protocol, sourceAddress, sourcePort, destinationAddress, destinationPort, payload);
        return true;
    }

    private static bool TryStripEthernet(ReadOnlySpan<byte> packetBytes, out ReadOnlySpan<byte> ipPacket)
    {
        ipPacket = default;
        if (packetBytes.Length < 14)
        {
            return false;
        }

        var etherType = BinaryPrimitives.ReadUInt16BigEndian(packetBytes.Slice(12, 2));
        var offset = 14;
        if (etherType == 0x8100 && packetBytes.Length >= 18)
        {
            etherType = BinaryPrimitives.ReadUInt16BigEndian(packetBytes.Slice(16, 2));
            offset = 18;
        }

        if (etherType != 0x0800 || packetBytes.Length <= offset)
        {
            return false;
        }

        ipPacket = packetBytes[offset..];
        return true;
    }

    private static string FormatEndpoint(IPAddress address, int port)
        => $"{address}:{port}";

    private static ByteOrder ParseByteOrder(ReadOnlySpan<byte> magic)
    {
        if (magic.SequenceEqual(new byte[] { 0xD4, 0xC3, 0xB2, 0xA1 }) ||
            magic.SequenceEqual(new byte[] { 0x4D, 0x3C, 0xB2, 0xA1 }))
        {
            return ByteOrder.LittleEndian;
        }

        if (magic.SequenceEqual(new byte[] { 0xA1, 0xB2, 0xC3, 0xD4 }) ||
            magic.SequenceEqual(new byte[] { 0xA1, 0xB2, 0x3C, 0x4D }))
        {
            return ByteOrder.BigEndian;
        }

        throw new ArgumentException($"Unsupported PCAP magic value: {Convert.ToHexString(magic)}");
    }

    private static uint ReadUInt32(byte[] buffer, int offset, ByteOrder byteOrder)
    {
        var slice = buffer.AsSpan(offset, 4);
        return byteOrder == ByteOrder.LittleEndian
            ? BinaryPrimitives.ReadUInt32LittleEndian(slice)
            : BinaryPrimitives.ReadUInt32BigEndian(slice);
    }

    private static string ToCompactHex(byte[] bytes)
        => Convert.ToHexString(bytes).ToLowerInvariant();
}

internal sealed record PcapTimelineEntry(TimeSpan Offset, string Summary)
{
    public string ToDisplayLine()
        => $"+{Offset.TotalMilliseconds,7:0}ms {Summary}";
}

internal sealed record ParsedPacket(
    string Protocol,
    IPAddress SourceAddress,
    int SourcePort,
    IPAddress DestinationAddress,
    int DestinationPort,
    byte[] Payload);

internal enum ByteOrder
{
    LittleEndian,
    BigEndian,
}
