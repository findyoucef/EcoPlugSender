using System.Net;
using System.Net.Sockets;

internal sealed record EcoPlugResponse(byte[] Payload, IPEndPoint RemoteEndPoint);

internal static class EcoPlugClient
{
    public static UdpClient OpenClient(int? sourcePort = null, bool enableBroadcast = false)
    {
        var client = sourcePort is int port
            ? new UdpClient(new IPEndPoint(IPAddress.Any, port))
            : new UdpClient();
        client.EnableBroadcast = enableBroadcast;
        return client;
    }

    public static async Task SendAsync(IPAddress ipAddress, int port, byte[] packet)
    {
        using var client = OpenClient();
        var endpoint = new IPEndPoint(ipAddress, port);
        await client.SendAsync(packet, packet.Length, endpoint);
    }

    public static async Task SendToAsync(UdpClient client, IPEndPoint endpoint, byte[] packet)
    {
        await client.SendAsync(packet, packet.Length, endpoint);
    }

    public static async Task<IReadOnlyList<EcoPlugResponse>> SendAndReceiveAsync(
        UdpClient client,
        IPEndPoint endpoint,
        byte[] packet,
        int duplicateCount,
        int duplicateGapMs,
        int responseIdleTimeoutMs)
    {
        for (var i = 0; i < duplicateCount; i++)
        {
            await SendToAsync(client, endpoint, packet);
            if (i + 1 < duplicateCount && duplicateGapMs > 0)
            {
                await Task.Delay(duplicateGapMs);
            }
        }

        return await ReceiveUntilIdleAsync(client, responseIdleTimeoutMs);
    }

    public static async Task<IReadOnlyList<EcoPlugResponse>> ReceiveUntilIdleAsync(UdpClient client, int responseIdleTimeoutMs)
    {
        var responses = new List<EcoPlugResponse>();

        while (true)
        {
            var receiveTask = client.ReceiveAsync();
            var completedTask = await Task.WhenAny(receiveTask, Task.Delay(responseIdleTimeoutMs));
            if (completedTask != receiveTask)
            {
                break;
            }

            var response = await receiveTask;
            responses.Add(new EcoPlugResponse(response.Buffer, response.RemoteEndPoint));
        }

        return responses;
    }
}
