# AGENTS.md

## Repo Purpose

This repository is a standalone C# CLI for sending reverse-engineered UDP packets to ECO plugs.

It currently supports:

- power control with `on` / `off`
- rename with `rename`
- LAN plug discovery with `discover`
- packet decoding with `decode`
- capture inspection with `pcap-timeline`
- first-time plug provisioning with `provision`
- plug AP scanning with `find-plugs`
- end-to-end factory-reset setup with `configure`

This is not a generic networking library. It is a focused reverse-engineering utility for one ECO plug protocol family.

## Repo Layout

- `EcoPlugSender/Program.cs`
  CLI entrypoint, argument parsing, rename/discover orchestration.
- `EcoPlugSender/EcoPlugPacketBuilder.cs`
  Packet construction for power, rename, probe, info, read, commit, and broadcast packets.
- `EcoPlugSender/EcoPlugClient.cs`
  UDP send/receive helpers.
- `EcoPlugSender/EcoPlugPacketDecoder.cs`
  Human-readable packet breakdowns.
- `EcoPlugSender/EcoPlugPacketInspector.cs`
  Lightweight field extraction used by discovery/timeline logic.
- `EcoPlugSender/PcapTimeline.cs`
  PCAP summarizer for reverse-engineering workflows.
- `EcoPlugSender/PacketHex.cs`
  Hex parsing/formatting helpers.
- `EcoPlugSender/WifiController.cs`
  `IWifiController` interface, `WifiNetwork` record, platform factory, shared IPv4-wait helper, and the `ShellRunner` process wrapper.
- `EcoPlugSender/WindowsWifiController.cs`
  Windows backend. Scans via `WindowsNativeWifi`, connects/disconnects via `netsh wlan`, builds profile XML by hand (not `XmlDocument`).
- `EcoPlugSender/WindowsNativeWifi.cs`
  P/Invoke wrapper around `wlanapi.dll` (`WlanOpenHandle`, `WlanScan`, `WlanGetNetworkBssList`). Parses the raw BSS list by advancing a fixed header stride.
- `EcoPlugSender/LinuxWifiController.cs`
  Linux backend. Shells out to `nmcli` with `-t` (colon-separated, escape-aware) output parsing.
- `EcoPlugSender/MacWifiController.cs`
  macOS backend. Uses `networksetup` and the legacy `airport -s` tool.
- `README.md`
  User-facing usage docs.

## Build And Run

Primary build command:

```bash
dotnet build EcoPlugSender/EcoPlugSender.csproj
```

Run examples:

```bash
dotnet run --project EcoPlugSender -- on
dotnet run --project EcoPlugSender -- off
dotnet run --project EcoPlugSender -- rename --current-name "office temp13" --new-name "office temp14"
dotnet run --project EcoPlugSender -- discover --timeout-ms 5000 --decode
dotnet run --project EcoPlugSender -- decode --hex "16 00 05 00 ..."
```

If `dotnet` on `PATH` is missing the SDK, a fallback SDK has previously existed at `/tmp/dotnet-sdk`, but prefer the normal `dotnet` command first.

## Verification Strategy

There is no formal test suite.

Use these checks instead:

- `dotnet build EcoPlugSender/EcoPlugSender.csproj`
- `--dry-run --decode` for packet-shape verification
- live `rename` only when you intentionally want to change the real plug
- live `on` / `off` only when you are okay controlling the real plug

Examples:

```bash
dotnet EcoPlugSender/bin/Debug/net9.0/EcoPlugSender.dll on --dry-run --decode
dotnet EcoPlugSender/bin/Debug/net9.0/EcoPlugSender.dll off --dry-run --decode
dotnet EcoPlugSender/bin/Debug/net9.0/EcoPlugSender.dll rename --current-name "office temp13" --new-name "office temp14" --dry-run --decode
```

## Live Device Defaults

Current shared defaults in the CLI:

- IP: `192.168.68.126`
- Port: `80`
- Plug ID: `ECO-7806EDD6`
- Power packet name: `Heater`
- Discover timeout: `5000ms`
- Provision target: `192.168.4.1:80` (the plug's address while in AP mode)

`rename` intentionally does not default `--current-name`.

## Protocol Rules That Matter

### Power Packets

The power packet format is intentionally fixed to the original reverse-engineered layout.

Important expectations:

- command header: `16 00 05 00`
- sequence: `00 00 27 56`
- write marker at bytes `8..9`: `02 00`
- power tail:
  - `01 01` for `on`
  - `01` for `off`

Do not casually “normalize” the power packet builder around generic extension-length logic without checking the resulting packet bytes carefully.

### Rename Sessions

Rename only became reliable after moving away from replaying captured session values.

Important expectations:

- rename must generate a fresh session every run
- do not reintroduce hard-coded session constants for:
  - source port behavior
  - sequence bytes
  - `field116`
  - `field124`
- rename replays the observed 3-probe flow shape and background broadcast traffic from the Android app

If rename starts failing again, compare against fresh phone captures before simplifying the session logic.

### Discovery

`discover` sends the same style of 128-byte broadcast packets seen in Android captures:

- source port `8900`
- destinations:
  - `255.255.255.255:5888`
  - `255.255.255.255:25`

Flags:

- `--timeout-ms <ms>` — how long to listen (default `5000`)
- `--decode` — also print each received response (structured for plug advertisements, raw hex otherwise)

Plug identification scans the first 64 bytes of each reply for an `ECO-` ASCII prefix. This is deliberately layout-agnostic: request packets place firmware and plug ID at fixed offsets, but plug replies observed on port 25 shift those fields earlier, so a fixed-offset check rejects real plug advertisements. Scanning for the `ECO-` marker catches both forms.

### Provisioning Packets

The provision packet is 492 bytes: a 128-byte header in the same shape as the other command packets, followed by a 364-byte extension body.

Important expectations:

- command header: `04 00 05 00`
- the header reuses the same plug-id/name field layout used by power/rename (plug ID at 16-byte field, plug name at 32-byte field, bare plug ID, `field116`, `field124`)
- the 364-byte extension carries the home-WiFi SSID and passphrase the plug should join, a zip code, country code `001`, fixed marker blocks, and three cloud endpoints (`203.66.65.34`, `203.66.65.34`, `61.220.255.143`) plus the stock app's hardware token `SLqfKrdnFM`
- the packet is sent to `192.168.4.1:80` while the plug is still broadcasting its `ECO-XXXXXXXX` factory AP
- `sequenceBytes`, `field116`, and `field124` are generated fresh per run (same rule as rename — do not reintroduce hard-coded values from a single capture)

`configure` orchestrates scan → join plug AP → wait for `192.168.4.x` → send provision packet → reconnect host → `discover`. `provision` is the raw packet send for when you've already joined the plug AP yourself.

## WiFi Control

`find-plugs` and `configure` need to scan and join WiFi networks, so there is a small platform abstraction.

- `IWifiController` (in `WifiController.cs`) defines `ScanAsync`, `GetCurrentSsidAsync`, `ConnectAsync`, `DisconnectAsync`, `WaitForIPv4Async`.
- `WifiController.Create()` returns the right backend based on `RuntimeInformation.IsOSPlatform(...)`.
- `ShellRunner` (same file) is the single place that runs external processes for WiFi backends. It captures stdout/stderr and surfaces stdout when stderr is empty, so `netsh`/`nmcli` failures produce useful messages.

Backend-specific notes:

- **Windows** — scans via the Native WiFi API (not `netsh wlan show networks`, which returns stale/cached results and often only the connected SSID). `netsh wlan connect` is tried first so existing profiles (including group-policy-managed ones like corporate WiFi) are reused; we only fall back to `netsh wlan add profile` when no matching profile exists. Profile XML is built by hand with `StringBuilder` + `SecurityElement.Escape` because `XmlDocument.Save` writes `encoding="utf-16"` into the declaration, which conflicts with UTF-8 file writes and causes `netsh wlan add profile` to reject the file. On Windows 10+, Native WiFi scans silently return an empty list when Location Services are disabled — `WindowsNativeWifi.ScanAsync` retries once and then throws a pointed "enable Location Services" error.
- **Linux** — shells out to `nmcli`. Scan uses `nmcli device wifi rescan` then `-t -f SSID,SIGNAL,SECURITY device wifi list`. `-t` mode escapes literal colons as `\:`, so parsing uses a custom colon-splitter (do not `String.Split(':')`). Over SSH on a headless box, NetworkManager's default polkit rule rejects connect/disconnect because the session isn't `local+active`; `LinuxWifiController.ConnectAsync` catches that specific error and emits the polkit-override recipe.
- **macOS** — uses `networksetup` for connect/disconnect/current-SSID and the legacy `airport -s` (at `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport`) for scans. Untested on real hardware; changes should be verified against a live Mac before trusting them.

## Network Environment Notes

These tools are sensitive to where they run from.

Important implications:

- the machine running the CLI may not be on the same layer-2 segment as the plug
- ARP/MAC discovery may fail even when the host is reachable by IP
- `nmap -sn` may report the host down even when TCP `-Pn` confirms it is up

If the local environment cannot see the plug's MAC address directly, use whatever machine on the LAN owns the neighbor table for that subnet. In the current setup, Windows-side commands have been useful:

```bash
arp.exe -a 192.168.68.126
powershell.exe -NoProfile -Command "Get-NetNeighbor -IPAddress 192.168.68.126"
```

## Editing Guidance

- Keep the CLI simple. This project intentionally removed old compatibility branches and debug-only rename overrides.
- Prefer changing behavior in `Program.cs` and packet definitions in `EcoPlugPacketBuilder.cs` instead of adding indirection.
- Update `README.md` whenever the CLI surface or defaults change.
- If you add new packet inspection logic, keep `EcoPlugPacketInspector.cs` lightweight and use `EcoPlugPacketDecoder.cs` for verbose output.

## What Not To Reintroduce

Do not add back:

- Perl/Nest compatibility framing
- old `rename-flow` command names
- hidden compatibility aliases for removed commands
- session replay based on one historical packet capture
- `XmlDocument.Save` for building the Windows WLAN profile XML (its `encoding="utf-16"` declaration conflicts with the UTF-8 file write and breaks `netsh wlan add profile`)
- manual BSS iteration advancing by `ulIeOffset + ulIeSize`. Windows Native WiFi packs `WLAN_BSS_ENTRY` headers contiguously (360 bytes each), with IE data living at the end of the buffer; the correct stride is `headerOffset + i * sizeof(WLAN_BSS_ENTRY)`

The repo should stay clean, current, and focused on the working CLI.
