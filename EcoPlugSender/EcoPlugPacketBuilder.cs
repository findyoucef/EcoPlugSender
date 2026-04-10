using System.Text;

internal enum PlugPowerState
{
    Off,
    On,
}

internal static class EcoPlugPacketBuilder
{
    private static readonly byte[] WriteCommandHeader = { 0x16, 0x00, 0x05, 0x00 };
    private static readonly byte[] RenameCommandHeader = { 0x13, 0x00, 0x05, 0x00 };
    private static readonly byte[] ProbeCommandHeader = { 0x00, 0x00, 0x04, 0x00 };
    private static readonly byte[] InfoCommandHeader = { 0x05, 0x00, 0x05, 0x00 };
    private static readonly byte[] ReadCommandHeader = { 0x17, 0x00, 0x05, 0x00 };
    private static readonly byte[] CommitCommandHeader = { 0x23, 0x00, 0x05, 0x00 };

    private static readonly byte[] PowerSequence = { 0x00, 0x00, 0x27, 0x56 };
    private static readonly byte[] PowerExtensionBody = { 0x02, 0x00 };
    private static readonly byte[] CommitMarker = { 0x01, 0x00 };
    private static readonly byte[] FirmwareVersion = Encoding.ASCII.GetBytes("1.6.3");

    // The power command still uses the original fixed session fields from the Perl script.
    private static readonly byte[] DefaultPowerField116 = { 0x3E, 0x1F, 0xB4, 0x16 };
    private static readonly byte[] DefaultPowerField124 = { 0x5E, 0x75, 0xAA, 0x46 };

    public static byte[] BuildWritePacket(string plugId, string plugName, PlugPowerState state)
    {
        var normalizedPlugId = NormalizeFullPlugId(plugId);
        var barePlugId = StripEcoPrefix(normalizedPlugId);

        ValidateAsciiField("plug ID", normalizedPlugId, 16);
        ValidateAsciiField("plug name", plugName, 32);
        ValidateAsciiField("bare plug ID", barePlugId, 16);

        var buffer = BuildPacket(
            headerBytes: WriteCommandHeader,
            plugId: normalizedPlugId,
            plugName: plugName,
            sequenceBytes: PowerSequence,
            field116: DefaultPowerField116,
            field124: DefaultPowerField124,
            extensionBody: PowerExtensionBody);

        buffer.Add(0x01);
        if (state == PlugPowerState.On)
        {
            buffer.Add(0x01);
        }

        return buffer.ToArray();
    }

    public static byte[] BuildRenamePacket(
        string plugId,
        string currentName,
        string newName,
        byte[] sequenceBytes,
        byte[] field116,
        byte[] field124)
    {
        var normalizedPlugId = NormalizeFullPlugId(plugId);
        var barePlugId = StripEcoPrefix(normalizedPlugId);

        ValidateAsciiField("plug ID", normalizedPlugId, 16);
        ValidateAsciiField("current name", currentName, 32);
        ValidateAsciiField("new name", newName, 32);
        ValidateAsciiField("bare plug ID", barePlugId, 16);

        return BuildPacket(
            headerBytes: RenameCommandHeader,
            plugId: normalizedPlugId,
            plugName: currentName,
            sequenceBytes: sequenceBytes,
            field116: field116,
            field124: field124,
            extensionBody: BuildRenameBody(newName, barePlugId)).ToArray();
    }

    public static byte[] BuildProbePacket(string plugId, string currentName, byte[] sequenceBytes, byte[] field116, byte[] field124)
        => BuildPacket(ProbeCommandHeader, NormalizeFullPlugId(plugId), currentName, sequenceBytes, field116, field124, []).ToArray();

    public static byte[] BuildInfoPacket(string plugId, string currentName, byte[] sequenceBytes, byte[] field116, byte[] field124)
        => BuildPacket(InfoCommandHeader, NormalizeFullPlugId(plugId), currentName, sequenceBytes, field116, field124, []).ToArray();

    public static byte[] BuildReadPacket(string plugId, string currentName, byte[] sequenceBytes, byte[] field116, byte[] field124)
        => BuildPacket(ReadCommandHeader, NormalizeFullPlugId(plugId), currentName, sequenceBytes, field116, field124, []).ToArray();

    public static byte[] BuildCommitPacket(string plugId, string currentName, byte[] sequenceBytes, byte[] field116, byte[] field124)
        => BuildPacket(CommitCommandHeader, NormalizeFullPlugId(plugId), currentName, sequenceBytes, field116, field124, CommitMarker).ToArray();

    public static byte[] BuildConnectingBroadcastPacket(uint counter)
    {
        var timestamp = DateTime.Now;
        var packet = new byte[128];
        var yearBytes = BitConverter.GetBytes((ushort)timestamp.Year);
        var counterBytes = BitConverter.GetBytes(counter);

        yearBytes.CopyTo(packet, 24);
        packet[26] = (byte)timestamp.Month;
        packet[27] = (byte)timestamp.Day;
        counterBytes.CopyTo(packet, 28);

        return packet;
    }

    private static List<byte> BuildPacket(
        byte[] headerBytes,
        string plugId,
        string plugName,
        byte[] sequenceBytes,
        byte[] field116,
        byte[] field124,
        IReadOnlyCollection<byte> extensionBody)
    {
        var barePlugId = StripEcoPrefix(plugId);
        ValidateFixedBytes("header", headerBytes, 4);
        ValidateFixedBytes("sequence", sequenceBytes, 4);
        ValidateFixedBytes("field116", field116, 4);
        ValidateFixedBytes("field124", field124, 4);

        var extensionLength = (ushort)extensionBody.Count;
        var buffer = new List<byte>(128 + extensionLength);

        buffer.AddRange(headerBytes);
        buffer.AddRange(sequenceBytes);
        buffer.Add((byte)(extensionLength & 0xFF));
        buffer.Add((byte)((extensionLength >> 8) & 0xFF));
        buffer.AddRange(FirmwareVersion);
        buffer.Add(0x00);
        WritePaddedAscii(buffer, plugId, 16);
        buffer.AddRange(new byte[16]);
        WritePaddedAscii(buffer, plugName, 32);
        WritePaddedAscii(buffer, barePlugId, 16);
        buffer.AddRange(new byte[16]);
        buffer.AddRange(new byte[4]);
        buffer.AddRange(field116);
        buffer.AddRange(new byte[4]);
        buffer.AddRange(field124);
        buffer.AddRange(extensionBody);

        return buffer;
    }

    private static byte[] BuildRenameBody(string newName, string barePlugId)
    {
        var renameBody = new List<byte>(102);
        renameBody.AddRange(new byte[38]);
        WritePaddedAscii(renameBody, newName, 32);
        WritePaddedAscii(renameBody, barePlugId, 16);
        renameBody.AddRange(new byte[16]);
        return renameBody.ToArray();
    }

    private static string NormalizeFullPlugId(string plugId)
    {
        if (string.IsNullOrWhiteSpace(plugId))
        {
            throw new ArgumentException("Plug ID cannot be empty.");
        }

        return plugId.StartsWith("ECO-", StringComparison.OrdinalIgnoreCase)
            ? plugId.ToUpperInvariant()
            : $"ECO-{plugId.ToUpperInvariant()}";
    }

    private static string StripEcoPrefix(string plugId)
    {
        return plugId.StartsWith("ECO-", StringComparison.OrdinalIgnoreCase)
            ? plugId[4..]
            : plugId;
    }

    private static void WritePaddedAscii(List<byte> buffer, string value, int fieldLength)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        buffer.AddRange(bytes);

        for (var i = bytes.Length; i < fieldLength; i++)
        {
            buffer.Add(0x00);
        }
    }

    private static void ValidateAsciiField(string fieldName, string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{fieldName} cannot be empty.");
        }

        foreach (var character in value)
        {
            if (character > 0x7F)
            {
                throw new ArgumentException($"{fieldName} must be ASCII.");
            }
        }

        if (Encoding.ASCII.GetByteCount(value) > maxLength)
        {
            throw new ArgumentException($"{fieldName} must fit within {maxLength} bytes.");
        }
    }

    private static void ValidateFixedBytes(string fieldName, byte[] value, int length)
    {
        if (value.Length != length)
        {
            throw new ArgumentException($"{fieldName} must be exactly {length} bytes.");
        }
    }
}
