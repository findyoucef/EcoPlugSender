# AGENTS.md

## Repo Purpose

Standalone C# CLI for sending reverse-engineered UDP packets to ECO smart plugs. Supports LAN control (`on`/`off`/`rename`/`discover`/`find-plugs`), first-time provisioning (`provision`/`configure`), cloud-relayed control via the plug's rendezvous server (`cloud-on`/`cloud-off`/`cloud-enroll`/`cloud-unenroll`), and packet introspection (`decode`/`pcap-timeline`).

This is a focused reverse-engineering utility for one ECO plug protocol family, not a general networking library.

## Repo Layout

- `EcoPlugSender/Program.cs` — CLI entrypoint, argument parsing, command orchestration, auto-resolve.
- `EcoPlugSender/EcoPlugPacketBuilder.cs` — Packet construction for every command (power, rename, probe, info, read, commit, provision, cloud wrapper, broadcast).
- `EcoPlugSender/EcoPlugClient.cs` — UDP send/receive helpers.
- `EcoPlugSender/EcoPlugPacketDecoder.cs` — Human-readable packet breakdowns (for `--decode`).
- `EcoPlugSender/EcoPlugPacketInspector.cs` — Lightweight field extraction for discover / timeline.
- `EcoPlugSender/PcapTimeline.cs` — PCAP summarizer for reverse-engineering.
- `EcoPlugSender/PacketHex.cs` — Hex parsing / formatting.
- `EcoPlugSender/WifiController.cs` — `IWifiController` interface, platform factory, shared IPv4-wait and `ShellRunner`.
- `EcoPlugSender/WindowsWifiController.cs` — Scans via `WindowsNativeWifi`, connects via `netsh wlan`, hand-built profile XML.
- `EcoPlugSender/WindowsNativeWifi.cs` — P/Invoke around `wlanapi.dll`.
- `EcoPlugSender/LinuxWifiController.cs` — `nmcli -t` shell-out.
- `EcoPlugSender/MacWifiController.cs` — `networksetup` + legacy `airport`.
- `README.md` — User-facing docs.

## Build And Run

```bash
dotnet build EcoPlugSender/EcoPlugSender.csproj
dotnet run --project EcoPlugSender -- on
dotnet run --project EcoPlugSender -- off
dotnet run --project EcoPlugSender -- discover --decode
dotnet run --project EcoPlugSender -- cloud-on
```

## CLI Behavior Model

**Auto-resolve is the core UX.** On-LAN commands (`on`, `off`, `rename`, `cloud-*`) start with a ~3s LAN discover broadcast and auto-fill missing `--plug-id` / `--ip` / `--server` / `--token` / `--name` from the reply. `provision` / `configure` resolve the plug ID from the WiFi SSID instead (the host is connected to the plug's AP during provisioning). Explicit flags always win.

**Off-LAN invocations require `--no-resolve`** plus all plug-specific fields passed explicitly:

```bash
EcoPlugSender cloud-on --no-resolve --plug-id ECO-XXXXXXXX --name MyPlug \
    --server <plug-cloud-ip> --token <10-char-token>
```

Harvest `--server` and `--token` from a prior on-LAN `discover --decode`.

## Rules That Matter (Anti-Patterns)

These are things that were wrong at some point in this repo's history. Do not regress them.

### No plug-specific defaults

Plug ID, LAN IP, plug name, cloud server IP, and hardware token are **per-plug**, resolved per-command. Do not reintroduce literal defaults for any of them. Protocol-level defaults (LAN port 80, cloud port 11621, provision target `192.168.4.1:80`, discover timeout 5000ms, country code `001`) are fine.

### Provision cloud-IP + token slots stay zeroed

The 492-byte provision packet has three 16-byte cloud-endpoint slots and a 10-byte hardware-token slot. The plug ignores all four — verified 2026-04-17 by provisioning with zeros and watching the plug join home WiFi with its firmware-baked values intact. Do not reintroduce literal cloud IPs (e.g. `203.66.65.34`) or a literal token (e.g. `SLqfKrdnFM`) in `BuildProvisionExtension`. Those bytes are skipped by the plug; hardcoding them makes the CLI look tied to one device.

### Hardware token is per-plug and firmware-baked

The 10-byte ASCII token at cloud-wrapper `[0x0c..0x15]` is **per-plug**, not global. Surfaced in the LAN discover broadcast at offset 338..347. The server validates it: with the correct token the relay response header carries the plug's WAN endpoint and the plug physically toggles; with the wrong token the relay still ACKs but omits the WAN endpoint and the plug does not toggle.

Do not reintroduce a "shared default" token or a fallback that silently uses one.

### Rendezvous server is per-plug

Each plug ships with its own firmware-baked cloud-server IP (surfaced in the LAN discover broadcast at offset 272..283). `203.66.65.34` is one example, `210.61.12.186` is another. Always source the server from discover or `--server`; don't hardcode.

### Fresh session fields per run (rename, provision, cloud path)

`sequenceBytes`, `field116`, `field124` must be randomized fresh per run for rename, provision, and every cloud-path command. Replaying captured values caused earlier rename + cloud-path bugs where packets got cleanly ACK'd but the plug silently refused to act.

The LAN power builder (`BuildWritePacket`) still uses hardcoded session constants from the original Perl reference — fine for direct LAN control, broken for cloud relay. `BuildWritePacketWithSession` is the cloud-compatible variant.

### Cloud wrapper rules

- Outer marker: `9a 0c 00 00 d9 09 00 00`
- Outer session key at `[0x08..0x0b]` MUST equal the inner packet's `field124` (inner bytes `124..127`). Observed in every phone-side capture.
- Inner length (LE u32) at `[0x40..0x43]`; inner bytes start at `[0x44]`.
- Cloud OFF requires a **130-byte** inner cmd=0x16 (tail `01 00`), not the 129-byte LAN OFF shape (tail `01`). Pad with one trailing zero.

### `cloud-unenroll` invalidates the session at the relay

A cmd=0x17 read with a fresh random session key makes the relay go silent for subsequent cmd=0x16 until `cloud-enroll` (wrapped cmd=0x05) revives it. Behavior mirrors what the Android app sends on tap-unenroll. Do not assume unenroll is a no-op.

## Security Model (Summary)

- Plug hardware token is firmware-baked per-plug and **persistent across factory reset + re-provisioning**. Factory reset is NOT an owner-side revocation mechanism: once an attacker has harvested a plug's token off the LAN (via `discover`), they retain remote control indefinitely.
- All traffic (LAN and cloud relay) is plaintext UDP, no TLS.
- Cloud relay validates token server-side (correct-token-only responses include the plug's WAN endpoint); LAN commands perform no authentication.
- Full cloud-architecture details (wrapper format, validation matrix, enroll/unenroll semantics) live in the `project_cloud_architecture` memory if you need them.

## WiFi Control

`find-plugs`, `provision`, and `configure` scan and join WiFi networks.

- **Windows**: Native WiFi API (`wlanapi.dll`) for scans, `netsh wlan` for connect/disconnect. Profile XML is built by hand (not `XmlDocument`). On Windows 10+, scan results require Location Services enabled.
- **Linux**: `nmcli -t` (colon-separated, escape-aware). Over SSH, NetworkManager's default polkit rule refuses connect/disconnect — drop a polkit override for your user to allow it (see README).
- **macOS**: `networksetup` + legacy `airport`.

## Discover Protocol Notes

- Source port: `8900`
- Destinations: `255.255.255.255:5888` and `255.255.255.255:25`
- Plug identification scans the first 64 bytes of each reply for an `ECO-` ASCII prefix. Plug replies observed on port 25 shift firmware / plug-ID fields earlier than request packets, so a fixed-offset check rejects them — the marker scan catches both forms.

## Verification Strategy

No formal test suite. Use:

- `dotnet build EcoPlugSender/EcoPlugSender.csproj`
- `--dry-run --decode` for packet-shape verification without hitting the plug
- Live `on` / `off` / `rename` / `cloud-*` only when you're okay controlling the real plug

**Critical for cloud-path testing**: do NOT trust "relay ACK'd, N responses received" as proof of state change. The relay will happily ACK packets the plug silently drops (wrong token, expired session, replayed constants). Always confirm the physical toggle with the user before declaring a cloud operation working.
