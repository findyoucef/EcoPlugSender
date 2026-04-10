internal static class PacketHex
{
    public static string Format(ReadOnlySpan<byte> packet)
    {
        if (packet.Length == 0)
        {
            return string.Empty;
        }

        var parts = new string[packet.Length];
        for (var i = 0; i < packet.Length; i++)
        {
            parts[i] = packet[i].ToString("X2");
        }

        return string.Join(" ", parts);
    }

    public static byte[] Parse(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException("Hex packet cannot be empty.");
        }

        var normalized = input
            .Replace(",", " ", StringComparison.Ordinal)
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Trim();

        if (normalized.Contains(' '))
        {
            var tokens = normalized.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return tokens.Select(ParseByteToken).ToArray();
        }

        normalized = normalized.Replace("0x", string.Empty, StringComparison.OrdinalIgnoreCase);
        if (normalized.Length % 2 != 0)
        {
            throw new ArgumentException("Contiguous hex input must contain an even number of characters.");
        }

        var bytes = new byte[normalized.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            var token = normalized.Substring(i * 2, 2);
            bytes[i] = ParseByteToken(token);
        }

        return bytes;
    }

    private static byte ParseByteToken(string token)
    {
        var normalized = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? token[2..]
            : token;

        if (normalized.Length != 2 || !byte.TryParse(normalized, System.Globalization.NumberStyles.HexNumber, provider: null, out var value))
        {
            throw new ArgumentException($"Invalid hex byte: {token}");
        }

        return value;
    }
}
