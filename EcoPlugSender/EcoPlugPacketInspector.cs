using System.Text;

internal sealed record EcoPlugPacketFields(
    byte CommandCode,
    string? PlugName,
    string? RenameTargetName,
    byte[] SequenceBytes,
    byte[] UnknownReadbackBytes,
    byte[] Field116Bytes,
    byte[] Field124Bytes,
    byte[] TailBytes);

internal static class EcoPlugPacketInspector
{
    public static EcoPlugPacketFields Inspect(byte[] packet)
    {
        return new EcoPlugPacketFields(
            packet.Length >= 1 ? packet[0] : (byte)0x00,
            ReadAscii(packet, 48, 32),
            ReadRenameTargetName(packet),
            ReadBytes(packet, 4, 4),
            ReadBytes(packet, 112, 4),
            ReadBytes(packet, 116, 4),
            ReadBytes(packet, 124, 4),
            packet.Length > 128 ? packet[128..] : []);
    }

    public static bool LooksLikeEcoPacket(byte[] packet)
    {
        if (packet.Length < 128)
        {
            return false;
        }

        var command = packet[0];
        if (command is not (0x00 or 0x05 or 0x13 or 0x16 or 0x17 or 0x23))
        {
            return false;
        }

        return ReadAscii(packet, 10, 5) == "1.6.3";
    }

    private static string? ReadRenameTargetName(byte[] packet)
    {
        if (packet.Length < 128 + 70 || packet[0] != 0x13)
        {
            return null;
        }

        return ReadAscii(packet, 128 + 38, 32);
    }

    private static string? ReadAscii(byte[] packet, int offset, int length)
    {
        var bytes = ReadBytes(packet, offset, length);
        if (bytes.Length == 0)
        {
            return null;
        }

        return Encoding.ASCII.GetString(bytes).TrimEnd('\0');
    }

    private static byte[] ReadBytes(byte[] packet, int offset, int length)
    {
        if (offset < 0 || length <= 0 || packet.Length < offset + length)
        {
            return [];
        }

        return packet[offset..(offset + length)];
    }
}
