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
    private static readonly byte[] ProvisionCommandHeader = { 0x04, 0x00, 0x05, 0x00 };

    private static readonly byte[] ProvisionMarkerBlock1 = { 0xEA, 0x17, 0x04, 0x11, 0x17, 0x0F, 0x00, 0x00 };
    private static readonly byte[] ProvisionMarkerBlock2 = { 0x10, 0x2D, 0xFF, 0xFF };
    private static readonly byte[] ProvisionPriorityBlock =
    {
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
    };
    private static readonly byte[] ProvisionFlagsBlock = { 0x00, 0x03, 0x00, 0x00, 0x01, 0x00 };
    private const string ProvisionCloudIp1 = "203.66.65.34";
    private const string ProvisionCloudIp2 = "203.66.65.34";
    private const string ProvisionCloudIp3 = "61.220.255.143";
    private const string ProvisionCountryCode = "001";
    private const string ProvisionHardwareToken = "SLqfKrdnFM";

    private static readonly byte[] CloudWrapperMarker = { 0x9A, 0x0C, 0x00, 0x00 };
    private static readonly byte[] CloudWrapperType = { 0xD9, 0x09, 0x00, 0x00 };
    private static readonly byte[] CloudWrapperHardwareToken = Encoding.ASCII.GetBytes(ProvisionHardwareToken);
    public const int CloudWrapperLength = 1092;
    public const int CloudWrapperInnerOffset = 0x44;
    private const int CloudWrapperInnerLengthOffset = 0x40;

    private static readonly byte[] PowerSequence = { 0x00, 0x00, 0x27, 0x56 };
    private static readonly byte[] CommitBody = { 0x01, 0x00 };
    private static readonly byte[] FirmwareVersion = Encoding.ASCII.GetBytes("1.6.3");

    // Bytes 8..9 are a command-type marker, not a computed extension length.
    // Per the original Perl reference: 0x02 0x00 = Write, 0x00 0x00 = Read/Probe/Info.
    private static readonly byte[] WriteCommandMarker = { 0x02, 0x00 };
    private static readonly byte[] ReadCommandMarker = { 0x00, 0x00 };

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

        var tail = state == PlugPowerState.On
            ? new byte[] { 0x01, 0x01 }
            : new byte[] { 0x01 };

        return BuildPacket(
            headerBytes: WriteCommandHeader,
            plugId: normalizedPlugId,
            plugName: plugName,
            sequenceBytes: PowerSequence,
            field116: DefaultPowerField116,
            field124: DefaultPowerField124,
            commandMarker: WriteCommandMarker,
            trailingBytes: tail).ToArray();
    }

    public static byte[] BuildWritePacketWithSession(
        string plugId,
        string plugName,
        PlugPowerState state,
        byte[] sequenceBytes,
        byte[] field116,
        byte[] field124)
    {
        var normalizedPlugId = NormalizeFullPlugId(plugId);
        var barePlugId = StripEcoPrefix(normalizedPlugId);

        ValidateAsciiField("plug ID", normalizedPlugId, 16);
        ValidateAsciiField("plug name", plugName, 32);
        ValidateAsciiField("bare plug ID", barePlugId, 16);

        var tail = state == PlugPowerState.On
            ? new byte[] { 0x01, 0x01 }
            : new byte[] { 0x01 };

        return BuildPacket(
            headerBytes: WriteCommandHeader,
            plugId: normalizedPlugId,
            plugName: plugName,
            sequenceBytes: sequenceBytes,
            field116: field116,
            field124: field124,
            commandMarker: WriteCommandMarker,
            trailingBytes: tail).ToArray();
    }

    public static byte[] BuildCloudWrapperPacket(byte[] innerPacket, byte[] sessionKey)
    {
        if (innerPacket is null || innerPacket.Length == 0)
        {
            throw new ArgumentException("Inner packet required.", nameof(innerPacket));
        }

        if (sessionKey is not { Length: 4 })
        {
            throw new ArgumentException("Session key must be 4 bytes.", nameof(sessionKey));
        }

        if (CloudWrapperInnerOffset + innerPacket.Length > CloudWrapperLength)
        {
            throw new ArgumentException("Inner packet too large to fit in cloud wrapper.", nameof(innerPacket));
        }

        var buffer = new byte[CloudWrapperLength];
        Buffer.BlockCopy(CloudWrapperMarker, 0, buffer, 0x00, 4);
        Buffer.BlockCopy(CloudWrapperType, 0, buffer, 0x04, 4);
        Buffer.BlockCopy(sessionKey, 0, buffer, 0x08, 4);
        Buffer.BlockCopy(CloudWrapperHardwareToken, 0, buffer, 0x0C, CloudWrapperHardwareToken.Length);
        BitConverter.GetBytes((uint)innerPacket.Length).CopyTo(buffer, CloudWrapperInnerLengthOffset);
        Buffer.BlockCopy(innerPacket, 0, buffer, CloudWrapperInnerOffset, innerPacket.Length);
        return buffer;
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

        var renameBody = BuildRenameBody(newName, barePlugId);
        return BuildPacket(
            headerBytes: RenameCommandHeader,
            plugId: normalizedPlugId,
            plugName: currentName,
            sequenceBytes: sequenceBytes,
            field116: field116,
            field124: field124,
            commandMarker: LengthAsMarker(renameBody.Length),
            trailingBytes: renameBody).ToArray();
    }

    public static byte[] BuildProbePacket(string plugId, string currentName, byte[] sequenceBytes, byte[] field116, byte[] field124)
        => BuildPacket(ProbeCommandHeader, NormalizeFullPlugId(plugId), currentName, sequenceBytes, field116, field124, ReadCommandMarker, []).ToArray();

    public static byte[] BuildInfoPacket(string plugId, string currentName, byte[] sequenceBytes, byte[] field116, byte[] field124)
        => BuildPacket(InfoCommandHeader, NormalizeFullPlugId(plugId), currentName, sequenceBytes, field116, field124, ReadCommandMarker, []).ToArray();

    public static byte[] BuildReadPacket(string plugId, string currentName, byte[] sequenceBytes, byte[] field116, byte[] field124)
        => BuildPacket(ReadCommandHeader, NormalizeFullPlugId(plugId), currentName, sequenceBytes, field116, field124, ReadCommandMarker, []).ToArray();

    public static byte[] BuildCommitPacket(string plugId, string currentName, byte[] sequenceBytes, byte[] field116, byte[] field124)
        => BuildPacket(CommitCommandHeader, NormalizeFullPlugId(plugId), currentName, sequenceBytes, field116, field124, LengthAsMarker(CommitBody.Length), CommitBody).ToArray();

    public static byte[] BuildProvisionPacket(
        string plugId,
        string plugName,
        string ssid,
        string password,
        string zipCode,
        byte[] sequenceBytes,
        byte[] field116,
        byte[] field124)
    {
        var normalizedPlugId = NormalizeFullPlugId(plugId);
        var barePlugId = StripEcoPrefix(normalizedPlugId);

        ValidateAsciiField("plug ID", normalizedPlugId, 16);
        ValidateAsciiField("plug name", plugName, 32);
        ValidateAsciiField("bare plug ID", barePlugId, 16);
        ValidateAsciiField("SSID", ssid, 32);
        ValidateAsciiField("password", password, 32);
        ValidateAsciiField("zip code", zipCode, 12);

        var extension = BuildProvisionExtension(normalizedPlugId, plugName, barePlugId, ssid, password, zipCode);

        return BuildPacket(
            headerBytes: ProvisionCommandHeader,
            plugId: normalizedPlugId,
            plugName: plugName,
            sequenceBytes: sequenceBytes,
            field116: field116,
            field124: field124,
            commandMarker: LengthAsMarker(extension.Length),
            trailingBytes: extension).ToArray();
    }

    private static byte[] BuildProvisionExtension(
        string plugId,
        string plugName,
        string barePlugId,
        string ssid,
        string password,
        string zipCode)
    {
        var ext = new List<byte>(364);
        ext.AddRange(FirmwareVersion);
        ext.Add(0x00);
        WritePaddedAscii(ext, plugId, 16);
        ext.AddRange(new byte[16]);
        WritePaddedAscii(ext, plugName, 32);
        WritePaddedAscii(ext, barePlugId, 16);
        ext.AddRange(new byte[18]);
        ext.AddRange(ProvisionMarkerBlock1);
        ext.AddRange(ProvisionMarkerBlock2);
        WritePaddedAscii(ext, ssid, 32);
        ext.AddRange(new byte[32]);
        WritePaddedAscii(ext, password, 32);
        ext.AddRange(new byte[34]);
        WritePaddedAscii(ext, ProvisionCountryCode, 10);
        WritePaddedAscii(ext, zipCode, 12);
        WritePaddedAscii(ext, ProvisionCloudIp1, 16);
        WritePaddedAscii(ext, ProvisionCloudIp2, 16);
        WritePaddedAscii(ext, ProvisionCloudIp3, 16);
        ext.AddRange(ProvisionPriorityBlock);
        ext.AddRange(ProvisionFlagsBlock);
        WritePaddedAscii(ext, ProvisionHardwareToken, 10);
        ext.AddRange(new byte[20]);
        return ext.ToArray();
    }

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
        byte[] commandMarker,
        IReadOnlyCollection<byte> trailingBytes)
    {
        var barePlugId = StripEcoPrefix(plugId);
        ValidateFixedBytes("header", headerBytes, 4);
        ValidateFixedBytes("sequence", sequenceBytes, 4);
        ValidateFixedBytes("commandMarker", commandMarker, 2);
        ValidateFixedBytes("field116", field116, 4);
        ValidateFixedBytes("field124", field124, 4);

        var buffer = new List<byte>(128 + trailingBytes.Count);

        buffer.AddRange(headerBytes);
        buffer.AddRange(sequenceBytes);
        buffer.AddRange(commandMarker);
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
        buffer.AddRange(trailingBytes);

        return buffer;
    }

    private static byte[] LengthAsMarker(int length)
        => new byte[] { (byte)(length & 0xFF), (byte)((length >> 8) & 0xFF) };

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
