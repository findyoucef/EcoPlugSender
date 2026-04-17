using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

[SupportedOSPlatform("windows")]
internal static class WindowsNativeWifi
{
    private const uint ClientVersionWindowsVistaOrLater = 2;
    private const uint ErrorSuccess = 0;

    [DllImport("wlanapi.dll")]
    private static extern uint WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanScan(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pDot11Ssid, IntPtr pIeData, IntPtr pReserved);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanGetNetworkBssList(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        uint dot11BssType,
        [MarshalAs(UnmanagedType.Bool)] bool bSecurityEnabled,
        IntPtr pReserved,
        out IntPtr ppWlanBssList);

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr pMemory);

    [StructLayout(LayoutKind.Sequential)]
    private struct Dot11Ssid
    {
        public uint uSSIDLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ucSSID;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WlanRateSet
    {
        public uint uRateSetLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)]
        public ushort[] usRateSet;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WlanBssEntry
    {
        public Dot11Ssid dot11Ssid;
        public uint uPhyId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] dot11Bssid;
        public uint dot11BssType;
        public uint dot11BssPhyType;
        public int lRssi;
        public uint uLinkQuality;
        [MarshalAs(UnmanagedType.U1)]
        public byte bInRegDomain;
        public ushort usBeaconPeriod;
        public ulong ullTimestamp;
        public ulong ullHostTimestamp;
        public ushort usCapabilityInformation;
        public uint ulChCenterFrequency;
        public WlanRateSet wlanRateSet;
        public uint ulIeOffset;
        public uint ulIeSize;
    }

    public static async Task<IReadOnlyList<WifiNetwork>> ScanAsync(TimeSpan waitAfterScan, CancellationToken cancellationToken)
    {
        var openResult = WlanOpenHandle(ClientVersionWindowsVistaOrLater, IntPtr.Zero, out _, out var handle);
        if (openResult != ErrorSuccess)
        {
            throw new InvalidOperationException($"WlanOpenHandle failed: 0x{openResult:X8}");
        }

        try
        {
            var enumResult = WlanEnumInterfaces(handle, IntPtr.Zero, out var interfaceListPtr);
            if (enumResult != ErrorSuccess)
            {
                throw new InvalidOperationException($"WlanEnumInterfaces failed: 0x{enumResult:X8}");
            }

            Guid interfaceGuid;
            try
            {
                var itemCount = Marshal.ReadInt32(interfaceListPtr);
                if (itemCount <= 0)
                {
                    throw new InvalidOperationException("No WLAN interfaces present.");
                }

                var firstItemPtr = IntPtr.Add(interfaceListPtr, 8);
                var guidBytes = new byte[16];
                Marshal.Copy(firstItemPtr, guidBytes, 0, 16);
                interfaceGuid = new Guid(guidBytes);
            }
            finally
            {
                WlanFreeMemory(interfaceListPtr);
            }

            var scanResult = WlanScan(handle, ref interfaceGuid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (scanResult != ErrorSuccess)
            {
                throw new InvalidOperationException($"WlanScan failed: 0x{scanResult:X8}");
            }

            await Task.Delay(waitAfterScan, cancellationToken);

            var bssResult = WlanGetNetworkBssList(handle, ref interfaceGuid, IntPtr.Zero, 1 /* infrastructure */, false, IntPtr.Zero, out var bssListPtr);
            if (bssResult != ErrorSuccess)
            {
                throw new InvalidOperationException($"WlanGetNetworkBssList failed: 0x{bssResult:X8}");
            }

            try
            {
                return ParseBssList(bssListPtr);
            }
            finally
            {
                WlanFreeMemory(bssListPtr);
            }
        }
        finally
        {
            WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    private static IReadOnlyList<WifiNetwork> ParseBssList(IntPtr bssListPtr)
    {
        var count = Marshal.ReadInt32(bssListPtr, 4);
        var headerSize = Marshal.SizeOf<WlanBssEntry>();
        var perSsidBest = new Dictionary<string, WifiNetwork>(StringComparer.Ordinal);

        for (var i = 0; i < count; i++)
        {
            var entryPtr = IntPtr.Add(bssListPtr, 8 + i * headerSize);
            var entry = Marshal.PtrToStructure<WlanBssEntry>(entryPtr);

            var ssidLength = (int)Math.Min(entry.dot11Ssid.uSSIDLength, 32);
            var ssid = ssidLength > 0
                ? Encoding.UTF8.GetString(entry.dot11Ssid.ucSSID, 0, ssidLength)
                : string.Empty;

            var isOpen = (entry.usCapabilityInformation & 0x0010) == 0;
            var network = new WifiNetwork(ssid, (int)entry.uLinkQuality, isOpen);

            if (perSsidBest.TryGetValue(ssid, out var existing))
            {
                if ((network.SignalPercent ?? -1) > (existing.SignalPercent ?? -1))
                {
                    perSsidBest[ssid] = network;
                }
            }
            else
            {
                perSsidBest[ssid] = network;
            }
        }

        return perSsidBest.Values.ToList();
    }
}
