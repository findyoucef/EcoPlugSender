using System.Text;

internal static class EcoPlugPacketDecoder
{
    public static string Describe(byte[] packet)
    {
        if (LooksLikeResponse(packet))
        {
            return DescribeResponse(packet);
        }

        var commandCode = packet.Length >= 1 ? packet[0] : (byte)0x00;
        var extensionLength = packet.Length >= 10 ? packet[8] | (packet[9] << 8) : 0;
        var lines = new List<string>
        {
            $"Length: {packet.Length} bytes",
            $"Command: {DescribeCommand(commandCode)}",
            DescribeBytes(packet, 0, 4, "command header"),
            DescribeBytes(packet, 4, 4, "sequence"),
            DescribeBytes(packet, 8, 2, "extension length"),
            DescribeAscii(packet, 10, 5, "firmware"),
            DescribeBytes(packet, 15, 1, "separator"),
            DescribeAscii(packet, 16, 16, "full plug ID"),
            DescribeBytes(packet, 32, 16, "reserved"),
            DescribeAscii(packet, 48, 32, "plug name"),
            DescribeAscii(packet, 80, 16, "bare plug ID"),
            DescribeBytes(packet, 96, 16, "reserved"),
            DescribeBytes(packet, 112, 4, "unknown readback"),
            DescribeBytes(packet, 116, 4, "legacy field A"),
            DescribeBytes(packet, 120, 4, "reserved"),
            DescribeBytes(packet, 124, 4, "legacy field B"),
            DescribeTail(commandCode, packet),
        };

        if (packet.Length > 128)
        {
            lines.Add(string.Empty);
            lines.Add($"Extension bytes present: {packet.Length - 128} (header says {extensionLength})");
            lines.AddRange(DescribeExtension(commandCode, packet[128..]));
        }

        return string.Join(Environment.NewLine, lines);
    }

    public static bool LooksLikeResponse(byte[] packet)
    {
        if (packet.Length < 26)
        {
            return false;
        }

        if (packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0)
        {
            return false;
        }

        if (Encoding.ASCII.GetString(packet, 4, 5) != "1.6.3")
        {
            return false;
        }

        return packet[10] == 0x45 && packet[11] == 0x43 && packet[12] == 0x4F && packet[13] == 0x2D;
    }

    private static string DescribeResponse(byte[] packet)
    {
        var lines = new List<string>
        {
            $"Length: {packet.Length} bytes",
            "Format: ECO plug broadcast advertisement",
            DescribeBytes(packet, 0, 4, "header zeros"),
            DescribeAscii(packet, 4, 5, "firmware"),
            DescribeBytes(packet, 9, 1, "separator"),
            DescribeAscii(packet, 10, 16, "full plug ID"),
            DescribeBytes(packet, 26, 16, "reserved"),
            DescribeAscii(packet, 42, 32, "plug name"),
            DescribeAscii(packet, 74, 16, "bare plug ID"),
        };

        var tailOffset = 90;
        if (packet.Length > tailOffset)
        {
            lines.Add(string.Empty);
            lines.Add($"ASCII strings found after offset {tailOffset}:");
            var found = false;
            foreach (var line in FindAsciiRuns(packet, tailOffset, minRun: 4))
            {
                lines.Add(line);
                found = true;
            }

            if (!found)
            {
                lines.Add("  (none)");
            }
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static IEnumerable<string> FindAsciiRuns(byte[] packet, int startOffset, int minRun)
    {
        var i = startOffset;
        while (i < packet.Length)
        {
            if (!IsPrintable(packet[i]))
            {
                i++;
                continue;
            }

            var start = i;
            while (i < packet.Length && IsPrintable(packet[i]))
            {
                i++;
            }

            var length = i - start;
            if (length >= minRun)
            {
                var text = Encoding.ASCII.GetString(packet, start, length);
                yield return $"{FormatOffset(start, length),-11} {"ascii",-18} \"{text}\"";
            }
        }
    }

    private static bool IsPrintable(byte value) => value >= 0x20 && value <= 0x7E;

    private static string DescribeBytes(byte[] packet, int offset, int length, string label)
    {
        var slice = ReadSlice(packet, offset, length);
        var value = slice is null ? "<missing>" : PacketHex.Format(slice);
        return $"{FormatOffset(offset, length),-11} {label,-18} {value}";
    }

    private static string DescribeAscii(byte[] packet, int offset, int length, string label)
    {
        var slice = ReadSlice(packet, offset, length);
        var value = slice is null
            ? "<missing>"
            : $"\"{DecodeNullPaddedAscii(slice)}\"";

        return $"{FormatOffset(offset, length),-11} {label,-18} {value}";
    }

    private static string DescribeTail(byte commandCode, byte[] packet)
    {
        if (packet.Length <= 128)
        {
            return $"{FormatOffset(128, 0),-11} {"tail bytes",-18} <missing>";
        }

        var tailBytes = packet[128..];
        if (commandCode is 0x16 or 0x17 or 0x23)
        {
            var stateGuess = tailBytes.SequenceEqual(new byte[] { 0x01, 0x01 }) ? "on"
                : tailBytes.SequenceEqual(new byte[] { 0x01 }) || tailBytes.SequenceEqual(new byte[] { 0x01, 0x00 }) ? "off"
                : "unknown";

            return $"{FormatOffset(128, tailBytes.Length),-11} {"power bytes",-18} {PacketHex.Format(tailBytes)} ({stateGuess})";
        }

        return $"{FormatOffset(128, tailBytes.Length),-11} {"tail bytes",-18} {PacketHex.Format(tailBytes)}";
    }

    private static IEnumerable<string> DescribeExtension(byte commandCode, byte[] extension)
    {
        if (commandCode == 0x13 && extension.Length == 102)
        {
            return new[]
            {
                DescribeBytes(extension, 0, 38, "rename reserved"),
                DescribeAscii(extension, 38, 32, "new plug name"),
                DescribeAscii(extension, 70, 16, "bare plug ID"),
                DescribeBytes(extension, 86, 16, "rename trailing"),
            };
        }

        return new[]
        {
            DescribeBytes(extension, 0, extension.Length, "extension raw"),
        };
    }

    private static string DescribeCommand(byte commandCode)
    {
        return commandCode switch
        {
            0x00 => "0x00 (discovery/echo?)",
            0x05 => "0x05 (device info request/response)",
            0x13 => "0x13 (rename request/ack)",
            0x17 => "0x17 (status read)",
            0x23 => "0x23 (state write?)",
            _ => $"0x{commandCode:X2} (unknown)",
        };
    }

    private static byte[]? ReadSlice(byte[] packet, int offset, int length)
    {
        if (offset < 0 || length <= 0 || offset + length > packet.Length)
        {
            return null;
        }

        return packet[offset..(offset + length)];
    }

    private static string DecodeNullPaddedAscii(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        return text.TrimEnd('\0');
    }

    private static string FormatOffset(int offset, int length)
    {
        if (length <= 0)
        {
            return $"{offset}";
        }

        return length == 1 ? $"{offset}" : $"{offset}..{offset + length - 1}";
    }
}
