# ECO Plug Sender

A standalone CLI for sending reverse-engineered UDP control packets to ECO plugs.

The packet layout intentionally preserves the original reverse-engineered behavior:

- Write command header: `16 00 05 00`
- Fixed sequence bytes: `00 00 27 56`
- Fixed write marker: `02 00`
- Fixed firmware string: `1.6.3`
- Full plug ID field: 16 bytes, ASCII, null-padded
- Plug name field: 32 bytes, ASCII, null-padded
- Bare plug ID field: 16 bytes, ASCII, null-padded
- Fixed legacy bytes at offsets `116..119` and `124..127`
- Power bytes: `01 01` for `on`, `01` for `off`

## Usage

```bash
dotnet run --project EcoPlugSender -- on --dry-run --print-packet
dotnet run --project EcoPlugSender -- on --dry-run --decode
dotnet run --project EcoPlugSender -- off
dotnet run --project EcoPlugSender -- status
dotnet run --project EcoPlugSender -- on --plug-id ECO-XXXXXXXX --name MyPlug
dotnet run --project EcoPlugSender -- rename --current-name "office temp11" --new-name "office temp12"
dotnet run --project EcoPlugSender -- rename --current-name "office temp11" --new-name "office temp12" --dry-run --decode
dotnet run --project EcoPlugSender -- decode --hex "16 00 05 00 00 00 27 56 02 00 31 2E 36 2E 33 00"
dotnet run --project EcoPlugSender -- pcap-timeline --pcap /mnt/c/Users/baouchiy/Downloads/PCAPdroid_09_Apr_01_06_42.pcap --plug-ip 192.168.68.126
dotnet run --project EcoPlugSender -- discover --timeout-ms 5000 --decode
dotnet run --project EcoPlugSender -- find-plugs
dotnet run --project EcoPlugSender -- provision --ssid HomeWifi --password secret --zip 02139 --dry-run --decode
dotnet run --project EcoPlugSender -- configure --ssid HomeWifi --password secret --zip 02139
dotnet run --project EcoPlugSender -- cloud-on
dotnet run --project EcoPlugSender -- cloud-off
dotnet run --project EcoPlugSender -- cloud-enroll
dotnet run --project EcoPlugSender -- cloud-unenroll
eco update
eco update --check
```

Shared defaults:

- LAN port: `80`
- Cloud rendezvous port: `11621`
- Provision target: `192.168.4.1:80` (the plug's AP-mode address)
- Discover timeout: `5000ms`

Plug ID, LAN IP, cloud server, plug name, and hardware token are **not** defaulted — they're auto-resolved from a LAN discover broadcast at the start of each command (or from the WiFi SSID for `provision` / `configure`). Pass any of them explicitly to override, or `--no-resolve` to skip discovery entirely (required when operating off-LAN).

`rename` does not default `--current-name`. You have to provide the device's current stored name explicitly.

`--dry-run` builds the UDP payload without sending it.

`--decode` prints a structured field breakdown for the packet the tool just built.

`decode --hex "..."` decodes a pasted packet capture or hex dump without sending anything.

`rename --new-name "..."` is the working rename implementation. It generates a fresh rename session each run instead of replaying one old successful capture. It opens one direct UDP session, generates new session bytes, advances them through the rename steps, and then runs the latest successful 3-probe rename shape stage-by-stage while waiting for replies.

During `rename`, the tool also sends the same style of 128-byte broadcast “connecting” packets the phone app emits to `255.255.255.255:5888` and `255.255.255.255:25` from local source port `8900`.

In normal use, `rename` only needs `--current-name` and `--new-name`. When used with `--decode`, it prints both the generated packets and the plug's UDP replies so you can confirm the stored name the device returned.

The `office temp4 -> office temp5` capture also showed repeated 128-byte broadcast UDP packets to `255.255.255.255:5888` and `255.255.255.255:25` while the app displayed a “connecting” dialog. Those packets are mostly zeros except for the date/counter bytes, and `rename` replays that traffic in the background because it is still part of the app’s observable session behavior.

`pcap-timeline --pcap ...` prints a relative-time view of a capture. With `--plug-ip`, it keeps packets involving the plug plus the surrounding broadcast and DNS traffic, which is useful for comparing successful phone rename sessions against failed PC replays.

`discover` broadcasts the 128-byte "connecting" probe to `255.255.255.255:25` and collects replies for `--timeout-ms` (default 3000). With `--decode`, each reply is parsed for plug id, stored name, and reported IP/port, which is how the phone app enumerates plugs on the LAN.

`provision` builds and sends the 492-byte first-time-setup packet used when a plug is in AP mode. Required fields: `--ssid`, `--password`, `--zip`. Plug ID defaults to the connected AP's SSID (or the single `ECO-XXXXXXXX` SSID found by a scan); plug name defaults to the plug ID. The packet embeds the home-WiFi SSID/passphrase the plug should join, country code `001`, and fixed marker blocks. The cloud-endpoint and hardware-token slots are zeroed — the plug ignores them and uses its firmware-baked values for both. Default target is `192.168.4.1:80` (the plug's AP-mode address). Use `--dry-run --decode` to inspect the packet without sending.

`status` sends a cmd=0x05 info request to a plug and prints the raw response hex. Useful for protocol archaeology — firmware version, stored identity, and any non-obvious fields the plug reports. Tested 2026-04-17 against an ECO-7806EDD6: zero bytes change with a 1500W load connected, so this model has no current sensor. Other ECO plug SKUs may differ.

`probe-cmd --cmd 0xNN` sends a status-shaped packet with an arbitrary command byte as the leading byte (replacing `0x05`). Useful for enumerating which command codes the firmware responds to. Tested 2026-04-19: on indoor ECO-7806EDD6 / WiOn 50050 ECO-7806C23E, the firmware replies to 0x02, 0x05, 0x14, 0x15, 0x18, 0x20, 0x21, 0x22, 0x24; the outdoor ECO-7806988A additionally responds to 0x28 and 0x2C. Cmd=0x21 is the only one with a non-ACK-sized response — 172 bytes, including a 44-byte trailer that appears to be a reserved HLW8012 metering slot (stays all-zero on every unit tested, which all lacked the populated current-sense IC).

`find-plugs` scans nearby WiFi for SSIDs matching `ECO-XXXXXXXX` (the factory AP name of an unconfigured plug). Pass `--all` to print every scanned SSID instead of filtering.

`configure` orchestrates the full first-time setup: remember the current SSID → scan for an `ECO-*` plug AP (or use `--plug-ap` to target one by name) → join it as an open network → wait for a `192.168.4.x` lease → send the provision packet to `192.168.4.1:80` → reconnect the host to the original SSID → wait briefly → run `discover` so the freshly provisioned plug shows up on the home LAN. Required fields mirror `provision` (`--ssid`, `--password`, `--zip`).

WiFi control for `find-plugs` and `configure` is platform-specific: Windows uses the Native WiFi API (`wlanapi.dll`) for scans and `netsh wlan` for connect/disconnect, Linux uses `nmcli`, and macOS uses `networksetup` plus the legacy `airport` tool. On Windows 10+, scan results require Location Services enabled (Settings → Privacy → Location, including "Let desktop apps access your location").

On a headless Linux host reached over SSH, NetworkManager's default polkit rule refuses `nmcli` connect/disconnect because the session isn't `local+active`. To allow the tool to drive WiFi over SSH, drop a polkit override for your user:

```
sudo tee /etc/polkit-1/rules.d/50-ecoplug.rules > /dev/null <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.NetworkManager.") == 0 &&
        subject.user == "YOUR_USERNAME") {
        return polkit.Result.YES;
    }
});
EOF
```

Remove it with `sudo rm /etc/polkit-1/rules.d/50-ecoplug.rules` when you're done. Desktop/local sessions don't need this.

## Cloud Control

`cloud-on`, `cloud-off`, `cloud-enroll`, and `cloud-unenroll` drive the plug through its ECO rendezvous server (UDP :11621) instead of talking directly to the plug on the LAN. Each plug has its **own** rendezvous server IP and 10-char hardware token, both burned into firmware and surfaced in the LAN discover broadcast.

On-LAN, the CLI runs a discover broadcast at the start of the command and auto-populates `--server` / `--token` / `--plug-id` / `--name` from the reply. Off-LAN, pass them explicitly along with `--no-resolve`:

```bash
dotnet run --project EcoPlugSender -- cloud-on \
    --no-resolve --plug-id ECO-XXXXXXXX --name MyPlug \
    --server <plug-cloud-ip> --token <10-char-token>
```

Harvest the server IP and token from a prior on-LAN `discover --decode` run.

- `cloud-on` / `cloud-off` wrap a cmd=0x16 power packet in the 1092-byte rendezvous frame and send to the server, which relays it to the plug.
- `cloud-enroll` wraps a cmd=0x05 info lookup. On a plug whose cloud session has lapsed (fresh from factory, long idle, or after `cloud-unenroll`), run this once to re-establish session state before `cloud-on`/`cloud-off` will toggle again.
- `cloud-unenroll` wraps a cmd=0x17 read with a fresh random session key, which mirrors what the Android app sends when you tap "unenroll". Subsequent `cloud-on`/`cloud-off` requests get no reply from the relay until you run `cloud-enroll`.

All four accept the usual `--dry-run`, `--print-packet`, and `--decode` flags for packet inspection without sending.

## Self-update

`eco update` checks the [latest GitHub release](https://github.com/findyoucef/eco-releases/releases/latest) and, if the running binary is out of date, downloads the matching per-platform archive (`eco-win-x64.zip`, `eco-linux-x64.tar.gz`, or `eco-osx-arm64.tar.gz`), extracts it, and replaces the running executable in place. On Windows the current `eco.exe` is renamed to `eco.exe.old` before the new binary takes its place; the stale `.old` file is deleted automatically on the next `eco` run. On Linux/macOS the binary is overwritten directly.

`eco update --check` reports whether a newer release is available without downloading it.

Only works against the published `eco` binary — running `dotnet run -- update` from a source checkout is refused.
