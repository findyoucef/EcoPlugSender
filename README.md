# ECO Plug Sender

This repo now includes a standalone C# port of the ECO plug packet writer/sender from the original Perl script. The Nest code is not used by the C# tool.

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
dotnet run --project EcoPlugSender -- on --ip 192.168.1.102 --plug-id ECO-7806EDD6 --name Heater
dotnet run --project EcoPlugSender -- rename --ip 192.168.68.126 --current-name "office temp11" --new-name "office temp12"
dotnet run --project EcoPlugSender -- rename --ip 192.168.68.126 --current-name "office temp11" --new-name "office temp12" --dry-run --decode
dotnet run --project EcoPlugSender -- decode --hex "16 00 05 00 00 00 27 56 02 00 31 2E 36 2E 33 00"
dotnet run --project EcoPlugSender -- pcap-timeline --pcap /mnt/c/Users/baouchiy/Downloads/PCAPdroid_09_Apr_01_06_42.pcap --plug-ip 192.168.68.126
```

Defaults match the original Perl script:

- IP: `192.168.1.102`
- Port: `80`
- Plug ID: `ECO-7806EDD6`
- Plug name: `Heater`

`--dry-run` builds the UDP payload without sending it.

`--decode` prints a structured field breakdown for the packet the tool just built.

`decode --hex "..."` decodes a pasted packet capture or hex dump without sending anything.

`rename --new-name "..."` is the working rename implementation. It generates a fresh rename session each run instead of replaying one old successful capture. It opens one direct UDP session, generates new session bytes, advances them through the rename steps, and then runs the latest successful 3-probe rename shape stage-by-stage while waiting for replies.

During `rename`, the tool also sends the same style of 128-byte broadcast “connecting” packets the phone app emits to `255.255.255.255:5888` and `255.255.255.255:25` from local source port `8900`.

In normal use you only need `--current-name` and `--new-name`. When used with `--decode`, it prints both the generated packets and the plug's UDP replies so you can confirm the stored name the device returned.

The `office temp4 -> office temp5` capture also showed repeated 128-byte broadcast UDP packets to `255.255.255.255:5888` and `255.255.255.255:25` while the app displayed a “connecting” dialog. Those packets are mostly zeros except for the date/counter bytes, and `rename` replays that traffic in the background because it is still part of the app’s observable session behavior.

`pcap-timeline --pcap ...` prints a relative-time view of a capture. With `--plug-ip`, it keeps packets involving the plug plus the surrounding broadcast and DNS traffic, which is useful for comparing successful phone rename sessions against failed PC replays.
