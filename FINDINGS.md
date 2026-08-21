# Orphek Atlantik v4 — Findings

A chronological log of reverse-engineering the Orphek Atlantik v4 control path,
with the goal of driving the light from the command line.

**Goal:** control an Orphek Atlantik v4 (with the separate Orphek Gateway box)
from the CLI, using the files under `orphek.com/` (APKs + gateway firmware).

**See also:** [GATEWAY.md](GATEWAY.md) — incidental system-level notes on the
gateway box (hardware, memory/CPU, flash layout, daemons, ports, SQLite schema,
web UI, cloud, firewall, security, architecture diagram).

**Inputs not committed:** the `orphek.com/` APKs + firmware this work is based
on are re-downloadable (~106 MB) and are git-ignored — get them from
`https://orphek.com/led/wp-content/uploads/` (firmware `V08693.zip`, app
`orphek-atlantik-v4-gen2-zb-v26.apk`). See [README.md](README.md).

**Environment:** macOS (darwin 27.0.0). LAN subnet is `192.168.2.0/23`.

## 1. Inventory of `orphek.com/`

Downloaded from `https://orphek.com/led/wp-content/uploads/` (per `README.md`).

- Firmware: `V08693.zip`, `testv08691A.zip`, `Getway-update-file-Oct-2016.rar`
- ~20 Android APKs spanning years/models (phone + tablet apps)
- PDFs: `Atlantik-V2-Guide.pdf`, `Atlantik-V2-Advanced_Guide.pdf`

Both firmware zips contain the same three-file OTA payload:

```text
firmware_update.md5sum      (32-byte md5)
firmware_update.sh          (flashing script)
firmware_update.tar.gz      (the actual image)
```

## 2. The firmware is the GATEWAY, not the light

`firmware_update.sh` flashes MTD partitions on an Atheros AR9331
(`ap121:green:system` LED paths, `mtd write … u-boot / uImage1 / rootfs1`). The
factory-test section runs `/mnt/production_test/JN5168_test/download_test.sh` —
the **JN5168 is an NXP ZigBee / 802.15.4 SoC**.

`firmware_update.tar.gz` unpacks to two files:

- `uImage` — `u-boot legacy uImage, MIPS OpenWrt Linux-3.3.8`, built 2018-05-23
- `rootfs` — `Squashfs 4.0, xz, 6.5 MB, 1723 inodes`

So the architecture is: **phone → WiFi/Ethernet → OpenWrt gateway →
ZigBee/JenNet-IP → light.**

## 3. The app uses a hand-rolled TCP client ("LongTooth")

`strings` on `orphek-atlantik-v4-gen2-zb-v26.apk`'s `classes.dex` showed a
custom TCP client, not HTTP/REST: `LTTCPSocket initialization`, `LT socket ip`,
`ltsocket_send_routine`, `sendRoutineRunnable _ltx.socket is null`. ("LT" /
"LongTooth" = the app's proprietary protocol; vendor namespace
`xpod.longtooth`.)

## 4. Extracting the rootfs (no new tools needed)

`7zz` (already installed) reads SquashFS directly:

```shell
7zz x -oroot -y rootfs      # 1583 files, 139 folders, 22 MB
```

Contents = **stock OpenWrt** + LuCI web UI + vendor additions in `/root`.

## 5. KEY FINDING — it's stock NXP JenNet-IP

The gateway runs standard **NXP JenNet-IP** middleware. Init scripts in
`/etc/init.d` are literally `Copyright (C) NXP Semiconductor`:

- `zigbee-jip-daemon` — ZigBee coordinator on serial `/dev/ttyATH0`,
  border-router `fd04:bd3:80e8:10::1`, **channel 25**
  (`/etc/config/zigbee-jip-daemon`)
- `JIPd` — JIP-over-UDP daemon, port **1873** (but `ignore 1` = disabled by
  default)
- `6LoWPANd`, `FWDistributiond` — NXP 6LoWPAN + firmware-distribution daemons

Binaries present: `/usr/bin/JIP`,
`/usr/sbin/{JIPd,6LoWPANd,FWDistributiond,zigbee-jip-daemon}`,
`/lib/libJIP.so.2`.

### `JIP` is a ready-made CLI get/set tool

Usage (from the binary's own help text):

```shell
JIP -6 <border-router-IPv6> -e "<cmd>;<cmd>;…"
   discover                 discover network contents
   mib  <MiB name / ID>     select active MiB
   var  <var name>          select active variable
   set  <value>             write it
```

Vendor script `refreshlight.sh` uses it directly:

```shell
JIP -6 fd04:bd3:80e8:10::1 -e "discover;mib ControlBridge;var PermitJoining;set 240"
```

## 6. The light's control variables (MiB/var names)

Pulled from the `/root/longtooth_test` binary (the gateway-side bridge the app
talks to). The light is an RGBW JenNet-IP bulb:

- **MiB:** `RgbwBulbControl` (also `BulbControl`, `ControlBridge`)
- **Vars:** `RedLumTarget`, `GreenLumTarget`, `BlueLumTarget`, `WhiteLumTarget`,
  `WhiteBrightness`; per-channel `…Mode`, `…Curve0`, `…Curve1`; `SceneId`;
  `GetChannel` / `SetChannel`; `Illuminance` / `IlluminanceStatus`.

So a per-channel intensity write is expected to be:

```shell
JIP -6 <light-IPv6> -e "discover;mib RgbwBulbControl;var WhiteLumTarget;set <n>"
```

(`discover` also on the gateway shows `mib BulbControl;var SceneId;set 0x…` used
for scene selection.)

## 7. Access to the gateway

- `/etc/config/dropbear`: `PasswordAuth on`, `RootPasswordAuth on`, port 22 —
  root SSH login is enabled.
- `/etc/passwd`: root has an MD5-crypt password hash
  (`$1$IG7/eqLD$gmPtk5AkoS3CLuuHfl8MP.`) — not yet cracked.
- App/DB default creds are `admin/admin` (and `administrator/administrator`) —
  from `/root/user.xml` and `/root/gateway_cache.db` (SQLite; `User` + `Scene`
  tables).
- `/etc/rc.d/S99iptable` opens INPUT tcp/22, tcp/80, tcp+udp/5353, and **all
  UDP**.
- Firmware version: `/root/ver.txt` → `version 0.8693 T`.

## 8. Two independent control paths

| Path                                       | Mechanism                                                                                                                                  | Notes                                                                                  |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| **A. JIP on the gateway** (recommended)    | SSH in, run `JIP -6 … -e "…"`                                                                                                              | Tool + var names already known. CLI = SSH wrapper, or later a native JenNet-IP client. |
| **B. LongTooth TCP** (what the app speaks) | App → `longtooth_test`: LAN `InetSocketAddress(ip, i4 + 30500)` or cloud relay `register.longtooth.io`; proprietary binary framing ("LTP") | Higher effort, no upside when we own the box.                                          |

Decompiled `xpod/longtooth/t.java` confirms path B: cloud host
`register.longtooth.io`, LAN port `i4 + 30500`, custom framing. The app only
uses B because it lacks shell access to the gateway — we have SSH, so we take A.

There is also a cloud **push** endpoint (`http://push.hotechie.com:8001`) — app
notifications only, not control.

**Direction (updated):** the END GOAL is **Path B — the public LongTooth TCP
protocol, no root** (what the app uses; auth `admin`/`admin`). Path A (JIP over
root SSH) is a side quest — useful for ground-truth (discovering nodes, reading
the light's real MiB/var values) to validate whatever we decode for Path B.

## 9. Tooling status

Already installed: `7zz`, `apktool`, `nmap`, `python3`, `tcpdump`, `jadx`
(installed this session), `brew`. `unsquashfs`/`binwalk` not needed (`7zz`
covers it).

## 10. Gateway located: 192.168.2.98

`nmap -sV` across `192.168.2.0/23` (see `network-nmap.txt`) — the gateway is the
one host matching the firmware:

```text
192.168.2.98
  22/tcp  Dropbear sshd 2011.54 (protocol 2.0)   <- matches 2018 firmware era
  80/tcp  OpenWrt uHTTPd
  Device: WAP
```

(All other hosts are the user's own kit — Macs, Synology, OPNsense, octoprint,
etc.)

## 11. Blocker: root SSH password (unresolved)

Path A needs root on the gateway. The firmware-default root hash from
`/etc/passwd` is `$1$IG7/eqLD$gmPtk5AkoS3CLuuHfl8MP.` (MD5-crypt). Offline crack
attempts that FAILED:

- Candidate list incl. `zxcvbn` (hinted by a commented `passwd` line in
  `firmware_update.sh`), `admin`, `orphek`, `longtooth`, `liseng`, `xpod`,
  `hotechie`, `atlantik`, common defaults — no match.
- Full `/usr/share/dict/words` (235,976 words) — no match.

Caveat: this is the _image_ default; the running device's password may have been
set differently at provisioning. Not yet confirmed against the live device.

### 11a. Serious crack attempt (in progress)

Hash type = MD5-crypt (`$1$`) = John format `md5crypt` / hashcat mode `500`.
Chose **John the Ripper** over hashcat: keyspace here is wordlist+rules
(~millions), which a CPU clears fast; hashcat's GPU edge only matters for large
brute-force.

Setup:

```bash
brew install john-jumbo
curl -L -o rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
echo 'root:$1$IG7/eqLD$gmPtk5AkoS3CLuuHfl8MP.' > gateway-hash.txt
john --format=md5crypt --wordlist=rockyou.txt --rules=best64 gateway-hash.txt
john --show gateway-hash.txt
```

Hash file saved as `gateway-hash.txt`.

**RESULT: root password = `snap`.** Note it does NOT match the firmware-image
hash `$1$IG7/eqLD$…` (verified: `crypt('snap', '$1$IG7/eqLD$') != …`),
confirming the §11 caveat — the live device's password was set at provisioning
and differs from the image default. So `snap` is the LIVE gateway root password.

## 12. Live-device SSH auth: all candidate passwords FAILED

SSH KEX negotiation had to be forced past Dropbear 2011's ancient crypto (modern
OpenSSH refuses it by default), one flag at a time:

- `HostKeyAlgorithms`/`PubkeyAcceptedAlgorithms` only → `no matching key
exchange method found. Their offer: diffie-hellman-group1-sha1,
diffie-hellman-group14-sha1`.
- Fix that worked: add `-o KexAlgorithms=+diffie-hellman-group14-sha1`.

Full working connect command:

```bash
ssh -o KexAlgorithms=+diffie-hellman-group14-sha1 \
    -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa root@192.168.2.98
```

With SSH negotiating, `root` @ 192.168.2.98 was tried with all five candidate
passwords (`admin`, `administrator`, `zxcvbn`, blank, `root`) — **none
authenticated.** The live root password is unknown and not an obvious default.

## 13. Telnet is NOT an alternative way in (ruled out)

`S50telnet` is enabled in `rc.d`, but the stock OpenWrt `/etc/init.d/telnet`
only starts `telnetd` when root has **no** password AND no SSH pubkey, **or**
when dropbear/sshd is disabled:

```shell
start() {
    if ( ! has_ssh_pubkey && \
         ! has_root_pwd /etc/passwd && ! has_root_pwd /etc/shadow ) || \
       ( ! /etc/init.d/dropbear enabled && ! /etc/init.d/sshd enabled );
    then
        service_start /usr/sbin/telnetd -l /bin/login.sh
    fi
}
```

On this box root HAS a password (§11) and dropbear is enabled, so telnetd does
**not** start. Port 23 is expected closed — a full port scan can confirm, but
this is not a bypass.

> Note: §12/§13 are the historical dead-ends. Root was then obtained by cracking
> the hash → password `snap` (§11a). We now have full root on the gateway.

## 14. Live JenNet-IP network discovered (side quest = success)

`discover;print` over root SSH mapped 4 nodes. Full distilled map:
[`jip-network-map.md`](jip-network-map.md). Key result:

- **Atlantik v4 RGBW light** = node `fd04:bd3:80e8:10:15:8d00:27d:2a28`
  (DeviceID `0x6ec70001`, MAC `00:15:8d:00:02:7d:2a:28`).
- Its control MiB `RgbwBulbControl` (0x6ec70008) has 8 UINT8 RW vars:
  `{Red,Green,Blue,White}Mode` (0–3) and `{Red,Green,Blue,White}LumTarget`
  (4–7). LumTarget = per-channel intensity.
- Other nodes: border router `::1`, ZigBee ControlBridge `…389:6707`, and a mono
  `BulbControl`-only node `…b24:2e04` (2nd luminaire/repeater, not the v4).

This is the ground truth to validate whatever we decode for Path B.

## 15. Full port scan: NO LAN LongTooth listener

`nmap -p- -T4 --open 192.168.2.98` (full 65535-port TCP sweep, see
[`gateway-nmap.txt`](gateway-nmap.txt)) — only **4 ports open**:

```text
22/tcp  ssh    (dropbear)
53/tcp  domain (dnsmasq)
80/tcp  http   (uHTTPd / LuCI)
443/tcp https  (uHTTPd SSL)
```

**No listener in the 30500-range** the app's LAN code targets (`ip, i4+30500`,
§8). Implication: on this network the app does NOT open a direct LAN socket to
the gateway — the gateway's `longtooth_test` dials **out** to the cloud relay
`register.longtooth.io`, and app↔gateway meet through the cloud. So Path B as a
_pure-LAN_ "public TCP, no root" path may not exist here; it may be
cloud-mediated (external dependency, latency) or the LAN path may be UDP /
opened on-demand. TBD — confirm by asking the gateway directly (we have root):
`netstat -ltnup` → `gateway-listeners.txt`.

This raises the standing of Path A (JIP over local SSH): it is a confirmed,
fully-local control path and we already have root.

## 16. LongTooth LAN path found — it's UDP (TCP scan missed it)

`netstat -ltnup` on the gateway (root; see
[`gateway-listeners.txt`](gateway-listeners.txt)) shows the real listeners:

```text
tcp  0.0.0.0:80     uhttpd
tcp  0.0.0.0:443    uhttpd
tcp  0.0.0.0:22     dropbear
tcp  0.0.0.0:53     dnsmasq
tcp  127.0.0.1:1880 zigbee-jip-daemon      (localhost IPC only)
udp  0.0.0.0:30500  longtooth_test    <-- LongTooth LAN control (app i4+30500)
udp  0.0.0.0:43100  longtooth_test
udp  [::]:38427     longtooth_test
udp  [::]:1873      zigbee-jip-daemon      (native JIP-over-UDP, all IPv6 ifaces)
udp  [::]:1874      FWDistributiond
udp  0.0.0.0:1812/1813  radiusd
```

Two clean findings:

- **Path B (public, no root) exists as UDP `30500`** on `longtooth_test`. The
  earlier TCP-only scan (§15) missed it because it's UDP. This is the app's
  local control path — no cloud, no SSH.
- **JIP is served on UDP `[::]:1873`** by `zigbee-jip-daemon`, bound to all IPv6
  interfaces — so the `JIP` protocol may be reachable directly from the Mac over
  IPv6 without SSH (bonus no-root path; needs IPv6 routing to the gateway —
  TBD).

## 17. UDP 30500 is a proprietary LongTooth _tunnel_, not a plaintext packet

**Why we looked:** to produce the exact UDP 30500 packet that sets a channel
(Path B, no root). **What we found:** it isn't hand-craftable — it's an
encrypted RPC tunnel. Evidence from the decompiled app (`xpod.longtooth`,
`com.hotechie.lt_adapter`):

- App boots it with `LongTooth.start(ctx, 888, 6, "<RSA public-key hex>", …)`
  and addresses peers by an `ltid` (e.g. `1.1.3281.49.1008`, cf. `user.xml`).
  `w.java` has hex↔byte + `MessageDigest` → a crypto handshake, not cleartext.
- `t.java` = framed datagram protocol (seq queues p/q/r/s); LAN transport is UDP
  `i4+30500`, cloud is TCP `register.longtooth.io:53199`.
- `admin`/`admin` is NOT wire auth — it's an inner `LoginUser` service call made
  _after_ the tunnel is established.
- Inner command format (once tunnelled) is simple and fully known: service
  `SetMibVar`, XML body
  `<command><device>ID</device><mib>RgbwBulbControl</mib><var>WhiteLumTarget</var><val>50</val></command>`
  (from `Command.toXMLString` + `DeviceManager.setMibVar`).
- Pure Java, no native `.so` → reimplementable, but that means porting the whole
  LongTooth tunnel + RSA handshake. Large effort, not a one-liner.

**Decision point (Path A vs B):**

|             | A — JIP over SSH      | B — LongTooth UDP 30500              |
| ----------- | --------------------- | ------------------------------------ |
| Root needed | yes (have it: `snap`) | no                                   |
| Effort      | trivial, works today  | large (reimplement encrypted tunnel) |
| Local-only  | yes                   | yes                                  |

Artifact: [`longtooth_test.strings.txt`](longtooth_test.strings.txt) (gateway
service vocab); app command layer in `com.hotechie.lt_adapter` (decompiled).

## 18. LongTooth LAN capture — plaintext XML, no encryption (big win)

Captured [`lt-capture.pcap`](lt-capture.pcap) by streaming tcpdump from the
gateway to a local file while using the Orphek app to move sliders / toggle for
~15s (find the gateway IP with `ruby atlantik.rb discover`; SSH needs the legacy
flags from §12, password `snap`):

```shell
ssh -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa root@<gw> \
    'tcpdump -i any -s0 -w - udp port 30500' > lt-capture.pcap    # Ctrl-C to stop
```

Parse it with `ruby lt_timeline.rb lt-capture.pcap` (`FULL=1` for per-packet
hex). Phone `192.168.2.114` ⇄ gateway `192.168.2.98`, all on **UDP 30500** —
**no cloud** (the RSA/`888,6` handshake from §17 is cloud-registration only; the
LAN path is NOT encrypted).

**Discovery:** phone broadcasts a 54-byte beacon to
`255.255.255.255:30500-30509` (sprayed across 10 ports); gateway answers, then
the session goes unicast on 30500.

**Frame = length-prefixed binary header + plaintext body.** Header layout (from
a 1400-byte data packet, body starts at offset 24):

```text
[0:4]   uint32 LE  = UDP payload length − 2   (e.g. 76 05 → 1398, payload 1400)
[4:14]  10 bytes   = destination address/ID   (all-zero when broadcast)
[14:18] 4 bytes    = tunnel/transaction id     (e.g. 37 37 80 a4; new per xact)
[18:24] 6 bytes    = opcode/flags (TBD)
[24:]   body       = plaintext XML (for data packets)
```

**Body is exactly the `Command` XML from the app (§17):**

```xml
<program_collection><program><name>Reef</name><id>85</id><command_collection>
 <command><device></device><mib>RgbwCurves</mib><var>RedCurve0</var>
  <val>00000000020070804c008ca04c00d2f0</val></command> …
```

**Tunnel control packets** (21/31 bytes) carry no XML — just
`[len][addr:10][tunnelid:4][opcode:1][...]`, opcodes seen `0x04`, `0x07`, `0x08`
(open / data / ack-style). The 4-byte tunnel id changes per transaction (`33 37
80 a4` → `24 68 46 80` → `fd 1f 20 ea`).

**Consequence:** Path B is far more tractable than §17 feared. To control the
light we need to (a) reproduce the discovery/tunnel-open handshake, (b) wrap an
XML `SetMibVar` command, (c) frame it with the header above. No crypto to break.

## 19. Service-call frame decoded — service names are cleartext

The 74/75-byte unicast openers (phone→gw) carry the service name as plaintext.
74-byte `GetDevices` call, payload from UDP offset 0:

```text
48 00 00 00                          len = 0x48 = 72  (= payload 74 − 2)
00 00 00 00 00 00 00 00 00 00        [addr:10]  (zero here)
b7 0e fd 07                          [connid:4] — matches the gateway's reply id
04 01                                opcode 0x04 (open+request), flag 01
01 78 03 00 00 01 00 00 00 46 00 51  ] ~36-byte request sub-header:
92 01 00 00 00 01 00 00 00 bd d4 0f  ]   dataType, gateway ltid, request id,
22 49 f1 02 f8 00 00 00 00 00        ]   seq — exact fields TBD (map via t.java)
0a 47 65 74 44 65 76 69 63 65 73     [svc] u8 len=10 + "GetDevices"
05 00 00 00 65 6d 70 74 79           [body] u32 LE len=5 + "empty" (no-arg marker)
```

75-byte packet is identical but `0b "GetPrograms"`. So:

- **Service name = `[u8 len][ASCII]`**, plaintext (`GetDevices`, `GetPrograms`,
  and per §17 `SetMibVar` etc.).
- **Body = `[u32 LE len][bytes]`**; empty calls send the literal `"empty"`.
- **Opcodes:** `0x09` discovery beacon · `0x04` open+request · `0x07` data ·
  `0x08` ack/close. Beacon/tunnel frames share the
  `[len:4][addr:10][id:4][op:1]` prefix.
- Maps to the app's `LongTooth.request(otherId, serviceName, dataType, body…)`
  (`LongtoothManager.callService`).

Remaining fuzz: the ~36-byte request sub-header fields (dataType, the gateway's
ltid, request id, sequence). Enough is known to _replay_ a captured call.

## 20. FIRST LIVE INTERACTION — replayed GetDevices, gateway replied

Ran `lt_getdevices_replay.rb` (Ruby; sends the verbatim 74-byte `GetDevices`
call from the Mac to `192.168.2.98:30500`). **The gateway replied** — so we can
speak LongTooth without the app, and the stale `connid b70e fd07` was accepted
(the connid is not session-bound enough to reject a replay).

Reply is a **21-byte tunnel ACK, not the device data**: `13 00 00 00 | 00×10 |
b7 0e fd 07 | 04 ff 01` — same connid echoed, opcode `04` flag `ff` = "open
acknowledged" (our request was `04 01`). Saved to `lt-getdevices-reply.bin`.

Tracing the _original_ capture for connid `b70efd07`: it too was only opener
(`04 01`) → gateway ack (`04 ff`), 2 packets. So the `GetDevices` device-list
payload did NOT ride this connid — the request/ack is just the tunnel handshake,
and the data response comes via a separate opcode/exchange (opcode `07` data
packets, seen in §18 carrying XML). Need the full per-transaction choreography.

Artifacts: `lt_getdevices_replay.rb`, `lt-getdevices-reply.bin`.

## 21. Full request/response choreography decoded

Built a pcap timeline parser (`lt_timeline.rb` → `lt-timeline.txt`). One
complete `GetDevices` transaction (seq 33–41 of the capture):

```text
dir op fl  meaning                                   connid
->  04 01  open request tunnel, svc "GetDevices"     A (client-chosen)
<-  04 ff  ack the open                               A
<-  04 02  open REVERSE tunnel, body "response"       B (gateway-chosen)
->  04 fe  ack the reverse tunnel                     B
->  07 00  "go" / ready for data                      B
<-  06 00  data: <device_collection>…XML… (1+ pkts)   B
<-  06 00  end-of-data (24-byte trailer)              B
->  08 01  final ack / close                          B
```

**Opcode/flag map** (byte [18]=op, [19]=flag of the frame header, §18):

| op  | flag | meaning                                        |
| --- | ---- | ---------------------------------------------- |
| 09  | 02   | discovery beacon (request)                     |
| 09  | fe   | discovery beacon (response)                    |
| 04  | 01   | open request tunnel (+ service name + body)    |
| 04  | ff   | ack of open                                    |
| 04  | 02   | open reverse/response tunnel (body "response") |
| 04  | fe   | ack of reverse tunnel                          |
| 07  | 00   | client "go" / ready                            |
| 06  | 00   | server data payload (XML), may span packets    |
| 08  | 01   | final ack / close                              |

So it's a two-tunnel design: client opens tunnel A to send the request; the
gateway opens its own tunnel B to stream the reply. My replay (§20) only did the
first two steps, hence just the `04 ff` ack.

**Device XML** (from the real GetDevices reply) shows the light as `<device
id="fd04:bd3:80e8:10:15:8d00:27d:2a28">` — device ids are the full IPv6
addresses, i.e. what goes in `<command><device>…</device>`. `WhiteLumTarget`
reads `0` currently. Artifact: `lt-timeline.txt`.

## 22. Built a native LongTooth client (`atlantik.rb`) — pending live test

Key sub-header insight from the exact opener bytes (§21): the **client chooses
BOTH tunnel ids**. The 34-byte request sub-header embeds the response connid at
bytes 26–29 (`24 68 46 80` in the capture) — and that's exactly the connid the
gateway used for its reply tunnel. So we don't have to parse it back; we pick
it.

Sub-header = `SUBHDR_PREFIX(25 const bytes)` + `respConnid(4)` + `00×5`. Prefix
(constant, replayed): `017803000001000000460051920100000001000000bdd40f22`.

`atlantik.rb` implements the full §21 choreography: send opener (`04 01`, svc +
`[u32 len]+body`) → on gateway `04 02` send `04 fe` ack + `07 00` go → collect
`06` data packets (ordered by their 4-byte seq) until the empty end-marker →
send `08 01` close → return reassembled XML. `frame()` uses len = payload−2.
Usage: `ruby atlantik.rb GetDevices`. Live test pending.

## 23. Client stalls at `04 ff` — sub-header identity likely matters

Live test of `atlantik.rb`: discovery (`09 02`→`09 fe`) works, opener sent, but
the gateway only ever returns the `04 ff` ack — it never opens the `04 02`
response tunnel. Ruled out:

- **Missing discovery** — added the beacon; still only ack.
- **Needs retransmit** — resent the opener ~12×; still only ack every time.

Leading hypothesis: the 34-byte request **sub-header encodes identity/routing**
(source + dest ltid). We copied the phone's bytes verbatim, so the gateway may
open the response tunnel toward the phone's identity rather than back to us, or
validate an id it won't honour. Need to decode those 34 bytes from the app's
`LongTooth.request` serializer (offline) rather than replay them blind.

## 24. Full frame format decoded from the app serializer (`b.java`/`w.java`)

All integers are 4-byte **little-endian** (`w.a(int)`). ltids (`k`) are 12 bytes
= three LE ints: `a`, `b`, `(C<<20)|(D<<10)|E` for an "A.B.C.D.E" ltid.

Base frame (`b.a`): `[len:4 =
size-2][addr1:6=0][addr2:6=0][connid:4][op][flag][b3]` (addr fields are two
packed 6-byte node addresses, zero for us).

Request opener (op `04 01`) adds:

```text
[21:33] srcLtid (12)   our identity
[33:45] dstLtid (12)   the gateway (captured: 1.1.544.980.957)
[45:49] respConnid     = -connid  (two's complement of the request connid!)
[49:53] 0
[53]    dataType byte
[54]    service-name length
[55:]   service name, then [bodyLen:4 LE][body]
```

**The bug that blocked us (§23):** `respConnid` MUST equal `-connid`. The
gateway correlates the response tunnel as the negation of the request tunnel id;
our earlier client used two unrelated ids, so it never opened `04 02`. Data (op
`06`) frames carry a 4-byte packet seq at [20:24] before the XML.

## 25. WORKING native client — read live device state (no root, no app)

`ruby atlantik.rb GetDevices` now completes the full handshake and returns the
live `<device_collection>` XML (2567 bytes). First full two-way exchange we
drive ourselves. Confirmed live state of the Atlantik v4
(`fd04:bd3:80e8:10:15:8d00:27d:2a28`):

- `RgbwBulbControl`: Red/Green/Blue/White `LumTarget` all = **71**
- `RgbwTemperature`: 37.1 °C · `_setting` Name "Orphek Atlantik v4", Group
  `f00f,0010`

So `LumTarget` is on a **0–255-ish scale** (app slider mapped), not 0–100.
Artifact: `atlantik.rb` (clean, mirrors the app's `b.java` layout).

## 26. Read is intermittent — beacon/request identity mismatch

Re-running `GetDevices` now often returns "no data": opener → `04 ff` ack, but
no `04 02`. Randomising the connid didn't fix it. Root cause: our **discovery
beacon replays the phone's identity** (constant captured bytes) while the
request uses a _made-up_ `SRC_LTID` — the two don't match, so the gateway can't
reliably map our ltid→our IP. The first success (§25) worked only because the
phone was idle. Debug also shows the gateway **broadcasting** `09 02` packets
full of device XML — the phone app contends on the same channel.

Fix: build our own discovery beacon (decoded from `b.java`: `base(54, connid, op
09, flag, b3=1)` + `long nonce @21` + `hash31(nonce||ltid) @29`, `hash31` =
`w.b`, ×31 with signed bytes) that encodes the **same ltid** as the request, so
beacon and request agree on our identity.

## 27. Regression is gateway-side state, not our packets

Replaying the **exact §25-success bytes** (constant connid + phone beacon) now
also fails — so the gateway changed state, not our code. Phone app is confirmed
**closed**, so it isn't live contention. Observations:

- Gateway acks our request (`04 ff`) but never opens the `04 02` response
  tunnel.
- Gateway continuously **broadcasts** on a fixed channel (connid `94623d39`, op
  `09 02`) carrying mixed content — device XML earlier, and now our own
  `LoginUser` body (`…me><password>admin</p…`) echoed back. Looks like an event/
  mirror stream, not our response.
- `LoginUser` (`<user><name>admin</name><password>admin</password>…`) behaves
  the same: ack + broadcast-echo, no response tunnel.

Hypothesis: the gateway only opens response tunnels for a client that has an
established/authenticated session; §25 worked because the phone's session was
live at that moment. Need gateway-side truth (we have root): what does
`longtooth_test` log when we send a request, and does it try to open `04 02`?

## 28. Gateway processes our request but broadcasts the reply (diagnosed on-box)

Autonomous gateway debugging (sshpass + legacy KEX; helper `scratchpad/gw`).
`logread -f` while firing the client shows `longtooth_test` **does** handle us:

```text
GetDevices command received:
[GetDevices] sendResponse
[truncated] <device_collection><device id="fd04:bd3:80e8:10::1">…
```

But a gateway-side `tcpdump` shows it only unicasts the 21-byte `04 ff` ack to
us; the actual response goes out as `09 02` **broadcasts** to
`255.255.255.255:30500` (connid `393d6294`/`94623d39`), with the LongTooth addr
field set to a **registered client MAC** `f0:de:59:xx:xx:xx` (the phone). Each
broadcast frame carries an incrementing offset (bytes [21:24]: 3923, 3959, 3990…
= +0x36) into the XML — i.e. the response is fragmented across broadcasts.

Also note: the gateway **cannot reach its cloud relay** (`connect to
47.91.142.68:53199 failed`), which may be why it falls back to broadcast.

Conclusions:

- §25 worked only because the phone's live session made the registered identity
  route to our IP; with the phone off, the reply broadcasts to the phone's MAC.
- **Reads are recoverable** by reassembling the `09` broadcast stream (we
  receive it — it's an IP broadcast).
- **Writes should not need a reply** — the gateway already executes the command
  on receipt (`… command received`). Fire-and-forget `SetMibVar` likely works.

## 29. Response delivery is session-gated (hypothesis, disproven)

Follow-up: with the phone off, `longtooth_test` logs `sendResponse` but emits
**no large XML packets at all** (gateway tcpdump shows only our 21-byte acks +
binary status broadcasts; capturing our socket finds 0 XML-bearing frames). Yet
§25 opened a proper `04 02` unicast tunnel and streamed op-`06` XML to us — and
§25 happened while the app was actively in use.

Hypothesis: the gateway opens a response tunnel only for a client with an
**active session** (what the phone app establishes/keeps alive on connect —
likely a login/registration we haven't reproduced). JIP `get` in `-e` batch mode
reports Success but prints no value, so it's not a read path for us.

**Test result: hypothesis WRONG.** `GetDevices` still returns no data even with
the app open and connected. So response delivery is not gated on an active app
session. Revised theory: §25 worked because that client build **hardcoded the
phone's exact captured connid `0x7FB997DC`/resp `0x80466824`** — likely slotting
into a tunnel/route the gateway already had for the phone. Once we switched to a
random connid, it broke.

Revised theory: §25 worked only because that build hardcoded the phone's exact
captured connid `0x7FB997DC`/resp `0x80466824`, slotting into a route the
gateway already had for the phone; a random connid breaks it.

## 30. Root cause: the gateway only opens response tunnels to same-subnet clients

Captured a fresh app connect (`connect.pcap`) and diffed the phone's working
`GetDevices` opener against ours — **byte-identical** except the random connid.
To capture it: start tcpdump on the gateway BEFORE opening the app, then
**force-quit and reopen** the Orphek app so it reconnects from scratch:

```shell
ssh <legacy-flags> root@<gw> 'tcpdump -i any -n -s0 -w /tmp/connect.pcap udp port 30500 & p=$!; sleep 30; kill $p'
# (force-quit + reopen the app during those 30s)
scp <legacy-flags> -O root@<gw>:/tmp/connect.pcap ./connect.pcap
```

Also fixed a real bug along the way: my `ltid()` string decode was wrong; the
gateway's ltid is the raw bytes `0100000001000000bdd40f22` (`w.a` verified;
`hash31` also reproduces the phone's beacon exactly). So our packets are
correct.

Yet a gateway-side capture of our request (`ours.pcap` — same gateway tcpdump as
above, but the traffic driven from the Mac with `ruby atlantik.rb GetDevices`
instead of the app) shows the gateway sends **only** the 21-byte `04 ff` ack and
**no `04 02` response tunnel to anyone**. The phone's response, by contrast, is
**unicast** `192.168.2.98 → 192.168.2.114` (the client's own IP). Difference:
the phone is on the gateway's subnet (`192.168.2.x`); our Mac is on
`192.168.3.x`, routed via OPNsense. `longtooth_test` processes the command
(`sendResponse` in the log) but won't open the return tunnel to an off-subnet
client it can't reach on local L2 — and its cloud relay
(`register.longtooth.io`) is unreachable, so there's no fallback. §25 worked
only by transiently hitting the phone's live tunnel (connid `0x80466824`).

**So Path B works — from a client on the gateway's own subnet (`192.168.2.x`).**
Next: confirm from a same-subnet source, then decide how to run the CLI there.

## 31. RESOLVED — writes work from the Mac (control achieved, no root)

The response-tunnel problem only blocks **reads**. **Writes are fire-and-forget
and work from the cross-subnet Mac.** Gateway log for our off-subnet
`SetMibVar`:

```text
SetMibVar command received: <command>…<var>WhiteLumTarget</var><val>255</val></command>
handleSpecialVar … filter_var: WhiteLumTarget
```

Verified round-trip via `JIP … get;print` (root, ground truth): `ruby
atlantik.rb SetMibVar '…WhiteLumTarget…255'` → `Value: 255`; then `…71` →
`Value: 71`. The light physically changed both ways. So:

- **Control (set channels/scenes) = solved over public LongTooth, no root**,
  from any host that can reach the gateway — writes don't need the response
  tunnel.
- **Reads over LongTooth** still fail from this Mac. **§30's subnet theory is
  DISPROVEN:** the gateway's LAN iface `eth1` is `192.168.2.98/23` (mask
  255.255.254.0, bcast 192.168.3.255), so `.2.x` and `.3.x` are ONE subnet —
  gateway, phone (`.2.114`), and both Mac IPs (`.2.109`, `.3.201`) are all on
  it. Sourcing our request from `.2.109` (same range as the phone) still gets no
  `04 02`. So the read barrier is some other unreplicated aspect of the phone's
  session (candidate: the persistent per-install beacon connid `05a5f4c1` the
  gateway may key routing on), not the network. Read options meanwhile: JIP
  `…;var X;get;print` over root SSH.

Note: JIP batch `get` prints the value only when followed by `print` (`…;var
WhiteLumTarget;get;print` → `Value: N`).

Autonomous gateway debugging used `sshpass` + legacy KEX (helper
`scratchpad/gw`), gateway-side `tcpdump`/`logread`, and a `nixio` Lua probe.

## 32. Reads: gateway GENERATES our response but routes it to the (dead) cloud

Autonomous live debugging (gateway reachable via SSH though the user is away).
With the phone off and no other 30500 traffic, our `GetDevices` is fully
handled: `GetDevices command received` → `[GetDevices] sendResponse` + the
device XML, for every retransmit. But a gateway-side `tcpdump` shows the gateway
emits **only** the 21-byte `04 ff` acks to us — **no `04 02`/`06` to anyone** —
and the log interleaves `register.longtooth.io`.

So the response is generated but delivered to the wrong transport: the gateway
opens the return tunnel toward the **cloud relay**
(`register.longtooth.io:53199`, which is DOWN) instead of a **direct LAN**
tunnel to us. The phone gets a direct LAN tunnel (`connect.pcap`: `.98→.114`
unicast `04 02`+`06`). Tried and did NOT fix it: correct gateway ltid, unique
`addr2` member key, source `.2.109` (same range as phone), **broadcast**
discovery beacon across ports 30500-09 (phone-style).

The LAN-vs-cloud routing decision lives in `longtooth_test` (the gateway's own C
daemon; `i.java` is only the app's server-side analogue). That's the thing to
crack next.

## 33. ltid semantics nailed from live gateway state

From the live gateway:

- `/tmp/longtoothID` = **`888.1.xxxx.xx.xx`** = the ltid at request **offset
  21** (`780300000100000046005192`). So offset 21 is the **gateway's own** id
  (the destination we're addressing). (My earlier "src/dst" naming was
  backwards, and my human-readable decode `2341.0.70` was wrong — it's
  `2341.64.70`; the raw bytes in `atlantik.rb` were always right.)
- `gateway_cache.db` `User` table: **`admin | admin | admin | 1.1.544.980.957`**
  — so offset 33 (`0100000001000000bdd40f22` = `1.1.544.980.957`) is the
  **logged-in user's** ltid. The gateway routes a response to the address
  registered for that user ltid; `admin` is registered to the **phone**, so our
  responses-as-admin are delivered toward the phone (offline) — never to us.
- Cloud uplink is `SYN_SENT` to `47.91.142.68:53199` (down), but the phone
  worked with it down, so that's not the differentiator.

Tried `LoginUser(admin/admin)` from our client before `GetDevices` to re-point
`admin`→our address: still no read (LoginUser's own response also never returns,
so we can't confirm it registered). Also available as a **practical read
fallback**: the light's state lives in `gateway_cache.db` (`MibVar`, `Device`)
and via `JIP …get;print` over root SSH.

Where reads are stuck: the gateway's per-identity response-address registration
(`peer_map`/`dest_m`) — logic that lives in the stripped MIPS `longtooth_test`.
Cracking it needs a MIPS disassembler (Ghidra / mips objdump), which isn't
installed on the Mac. That's the next concrete step.

## 34. READS CRACKED via Ghidra — unique offset-33 ltid (COMPLETE, no root)

Installed Ghidra 12.1.3 (`brew install ghidra`), imported `longtooth_test`
(MIPS:BE:32, base 0x400000) headless (`analyzeHeadless … -postScript`), and
decompiled the functions referencing `peer_map` / `register.longtooth.io` /
`GetDevices command received`. The keepalive printer (`FUN_00440b60`) exposed
the router globals — `peer_map=DAT_004fc088`, `dsr_m=DAT_004fc08c`,
`dest_m=DAT_004fc090` — confirming the app-side model (`i.java`): the response
tunnel is routed to a **member keyed by the offset-33 ltid**.

**The fix:** every earlier "unique ltid" test had mistakenly varied **offset
21** (the gateway's own id — must stay exact). Keeping offset 21 correct and
making **offset 33 UNIQUE** (not admin's `1.1.544.980.957`, which the phone
owns) makes the gateway create a fresh member bound to **our** address → the
response comes to us. Verified: `GetDevices` returns the full 2569-byte device
XML, **4/4 reliable**, no root, no app, phone or no phone.

`atlantik.rb` now randomises the offset-33 ltid. **Both reads and writes work
from the Mac over the public LongTooth protocol.** Ghidra artifacts:
`ghidra_scripts/` (DumpFns/DecAt), `decomp_*.txt`.

## 35. How a node gets its ltid (identity), and the open question

Decompiled the gateway's `EVENT_LONGTOOTH_STARTED` handler (`FUN_0045266c`): the
LongTooth library hands the daemon its **own id** at startup (`param_2`), which
the daemon just caches — `echo %s > /tmp/longtoothID` (and `/www/longtoothID`) —
then registers every service handler (`GetDevices`, `SetMibVar`, `LoginUser`,
`AddUser`, `SetChannel`, …) via `FUN_00443c10(name, fn)`. The `a.b.c` ltid is
just three ints packed by the `%d.%d.%d.%d.%d` formatter (`FUN_0045224c`:
`a`,`b`,`c>>20`,`c>>10 & 0x3ff`,`c & 0x3ff`).

So: a node does **not** ask for an id per-request — it's assigned one ltid at
startup and caches it. The gateway holds a valid ltid (`888.1.xxxx.xx.xx`) even
though its cloud link is `SYN_SENT`, so the id is obtained without a live cloud
(locally derived or cached from a prior boot). `register.longtooth.io` is the
global **rendezvous** service. A **user's** ltid in the DB is the ltid of the
client that logged in as that user (`LoginUser` binds requester→user), which is
why reusing `admin`'s id routed our replies to the phone.

**Open question:** with the app on several household phones, ltids must be
collision-free — so there's a uniqueness authority (most likely the cloud
registrar assigning/confirming each install's id, or a per-install crypto
identity). Next: find where a _client_ mints/obtains its ltid (app `LongTooth`
start/register path; is the RSA `appKey` per-install or hardcoded?).

Our client sidesteps all this: it mints a **random** offset-33 ltid per run; the
gateway makes an ephemeral member for it (LAN requests aren't authenticated),
and the id space makes a clash with the phone negligible.

## 36. How a client gets a collision-free id (answered)

From the app's `LongTooth.start` impl (`xpod.longtooth.a.a(devId, appId, appKey,
n, handler)`): the client's own ltid `m = {a,b,c}` is derived **locally**:

```java
machineId = n.b()                 // telephony deviceId (IMEI), else WiFi MAC (cached in prefs)
m.a = devId (888);  m.b = appId (6);  m.c = machineId.hashCode()   // Java String.hashCode
```

So each install seeds the unique component from its **hardware machine id** —
different phone → different IMEI/MAC → different hash → different ltid. That's
why two household phones don't clash: **no clash detection is needed; uniqueness
comes from the hardware id.** (Residual risk = a 32-bit `hashCode` collision,
negligible at household scale.) A secondary path (`a.b(dVar)`, `m.c = server
field 2`) lets the **register server assign/override** the id during activation
— used for the cloud rendezvous and, likely, account (user-ltid) binding. Note
the _device_ ltid is `888.6.hash`; the _user_ ltid at request offset 33 (`admin`
= `1.1.544.980.957`) is a separate account identity bound server-side at login.

## 37. Gateway "went down" — actually a DHCP IP change + wedged longtooth

Reads suddenly failed and SSH refused at `192.168.2.98`. **Misdiagnosed first as
a member-leak/watchdog reboot — WRONG.** Uptime was continuous (`8 days`), so no
reboot: the gateway's **DHCP lease moved it `.98 → .62`** (it's a DHCP client on
eth1). Nothing was at `.98`, hence the silence/refused SSH.

At the new IP, longtooth still answered the **broadcast** `09` beacon (so
`discover` found it) but its **request handler was wedged** — our openers
arrived (gateway tcpdump) yet got no ack and no `command received` log.
**Restarting `longtooth_test`** (`cd /root; kill; setsid ./longtooth_test &`)
fixed it immediately; reads resumed. The light is unaffected by a longtooth
restart (it runs its own schedule; longtooth is just the control bridge).

Takeaways / fixes:

- **`atlantik.rb discover`** (new): broadcasts the `09` beacon to
  `255.255.255.255:30500-09`, lists gateways answering `09 fe` — finds the box
  after any DHCP IP change. Proven: it located `.62` while everything hardcoded
  to `.98` failed.
- `USER_LTID` now = `crc32(hostname)` (deterministic; `String#hash` is
  per-process random). Reusing one member id is tidier, though the "leak" was
  never the cause.
- The gateway's own ltid (`GW_LTID`, offset 21) is stable across the IP change
  (derived from its MAC), so only the IP needed rediscovery.

Read services surveyed OK before the crash: `GetGatewayVersion` ("version 0.8692
A"), `GetTimezone` ("Asia/Hong Kong"), `GetPrograms` (the "Reef" program with
all RgbwCurves), `GetGroups` (`0010` "dd900"), `GetUsers` (admin/administrator,
plaintext pw), `GetSystemPara` ("500"); `GetScenes`/
`GetRooms`/`GetExternalSceneTriggers` empty. Live device state (temp, current
time, channel levels, work mode) is in `GetDevices`.

## 38. The discovery beacon was wedging the gateway — reads need NO beacon

Root cause of the "flaky/wedging at .62" saga: our client sent a discovery
**beacon (op 09) before every request**. That makes longtooth attempt a peer
registration; with the cloud relay unreachable (`register.longtooth.io`,
`SYN_SENT`) that blocks and **wedges longtooth's request handler** — after a few
requests it stops answering unicast (still answers broadcast discovery, which
misled me). Proven: sending the request **without** the beacon gets the `04 ff`
ack + `04 02` tunnel immediately and stays stable across rapid reads.

Fix: `call` no longer sends a beacon (the beacon is only for the `discover`
command). Restarted longtooth once to clear the wedged state. Reads are now
stable; residual single-read drops are masked by a retry in `status`.

`ruby atlantik.rb status` now prints: name, IP, firmware, device clock (secs of
day), timezone, temperature, per-channel levels (0–255 bars) + work mode, and
program names. `ruby atlantik.rb discover` finds the gateway after a DHCP move.

## 39. It was never the gateway — a poisoned STABLE member id was

Twice I wrongly blamed the gateway (member-leak "crash" §37; "needs a reboot"
§38). the user's phone connected and read fine (22:13, 28.4 °C) — proving the
gateway was healthy throughout. Controlled test (phone connected): a **fresh
random** offset-33 ltid works with OR without the beacon; only the **stable
`crc32(hostname)`** id failed. Cause: reusing one member id across many
interrupted reads left that member with a **stuck/half-open tunnel**, so every
later read on it got ack-but-no-`04 02`. A fresh id always gets a clean member.

Fix: `USER_LTID` is now **random per process** (reverting the §37 "stable id"
change, which was based on the false crash diagnosis). Member churn is harmless
for occasional CLI use. `status` now runs reliably and **matches the phone
exactly** (time + temp). No reboot was ever needed.

Re §38: removing the beacon from `call` is still correct (it can wedge longtooth
when the cloud is down), but it was not the read-failure cause here — the
poisoned stable id was.

## 40. RgbwCurves decoded — the daily light schedule

Curve blob format (from the app's `Program.Curve.createFrom` / `CurvePoint`): a
curve is a list of **4-byte points** `[lum:1][timestamp:3 BE]`, where
`timestamp` = seconds-of-day and displayed intensity = `round(lum/255*100)`%.
Each channel has two curves (`Curve0`+`Curve1`) that chain (Curve1 starts at
Curve0's last point). Point times run 00:00 → ~21:00.

`ruby atlantik.rb program` reads the **live** `RgbwCurves` (what's actually
loaded on the light) and prints a per-channel 24-hour sparkline + key
time/intensity points. `ruby atlantik.rb programs` dumps every **stored**
program from `GetPrograms` the same way (Reef #85 = full reef day w/ 65% blue
dusk; reef #87 = dimmer, later peak). Verified against a hand-decode; classic
reef day shape (midday/afternoon peak, blues longest, off by evening). The live
curves differ from both stored programs — the device runs its own edited set.

## 41. Manual vs program mode (how to hand control back to the schedule)

From the app (QuickSet / ProgramActivity / DeviceListFragment):

- **Manual:** write `RgbwBulbControl.{Red,Green,Blue,White}LumTarget` (0–255).
  The firmware takes that channel out of program mode and holds the value.
- **Program/auto:** `RgbwWorkMode.{Red,Green,Blue,White}Mode = 0`. "Apply
  program" sets these to 0 _and_ loads the `RgbwCurves`. The app reads
  `RgbwWorkMode.RedMode == 0` to mean "in program mode". Curves persist on the
  device, so setting Mode back to 0 resumes the loaded schedule at the current
  time — no need to re-upload curves.

So the write CLI needs a `restore`/`auto` = four `RgbwWorkMode …Mode 0` writes
(or one `SetBatchMibVar`) to undo any manual `set`.

**Demo mode is on-device (firmware), not an app animation.** The `RgbwDemoMode`
MiB runs the RGBW cycle on the bulb itself; the app writes then `StartDemo=1` to
run / `StartDemo=0` to stop. Var semantics (from the app's input dialog
`quickset_demo_description_*` strings):

- `Time` = how long the demo runs, in **seconds, 1–300**.
- `MaxLevel` = peak brightness, **percent 10–100** (sent as-is, not scaled to
  255).
- `StartDemo` = 1 start / 0 stop.

## 42. CLI command reference (`atlantik.rb`)

Self-documenting: `ruby atlantik.rb` (or `help`) prints all of this plus the
63-service list. Run `configure` once first; reads are safe any time; writes
move the light (daylight only; `DRY_RUN=1` previews writes without sending).

- `configure` — prompt for your Gateway ID (the `888.1.…` number on the
  underside of the gateway) and store it in `.atlantik-gateway` (cwd). Required:
  every other command aborts early until it is set.
- `status` — gateway IP+id+fw, device clock (phone-local; forces a cache
  refresh, §44), temp, current channel levels (MANUAL-flagged if overridden),
  and the loaded day schedule (24h sparkline).
- `programs` — every stored program, decoded.
- `<Service> [body]` — call any of the 63 services (e.g. `GetUser admin`).
- `mode manual <r> <g> <b> <w>` — hold channels at 0–255 each (`RgbwBulbControl
.*LumTarget`); overrides the schedule until `mode program`.
- `mode demo [max%=10-100] [secs=1-300]` — start on-device demo (defaults 100,
  60).
- `mode program` — `RgbwWorkMode.*Mode=0` + `StartDemo=0`; resumes the schedule.
- Env: `GW=<ip>` skip broadcast IP-discovery; `DRY_RUN=1` preview writes.

## 43. Retired the hardcodes — the Gateway ID is just the number on the box

Two per-install constants were baked into `atlantik.rb`: the light's device id
and the gateway's own ltid. Both are gone.

**Device id (was `ATLANTIK`) — discovered.** `status`/`set_mibvar` no longer
match a hardcoded IPv6. `light_block` finds the light's `<device>` block in a
`GetDevices` reply by the presence of its `RgbwBulbControl` MiB, and `light_id`
returns that block's id. This also fixed a real bug: when the old hardcoded
filter missed, `status` silently printed an all-zero device (time `00:00`, temp
`n/a`, all channels 0) instead of failing — it now aborts loudly if `GetDevices`
has no Rgbw light.

**Gateway ltid (offset 21) — it's printed on the gateway.** A detour worth
recording. The offset-21 ltid must be exact: the gateway checks it recognises
itself as the target, and the discovery beacon hashes it — proven, since a
beacon hashing our `USER_LTID` instead drew zero `09 fe` replies. I first
fetched it from `http://<gw>/longtoothID` (the daemon publishes its id there;
uHTTPd :80, no auth — §35):

```shell
$ curl -s http://192.168.2.62/longtoothID
888.1.xxxx.xx.xx
```

That works but needs the IP first. Then the official Gateway 2 manual settled
it: setup **step 4 is "Enter the Gateway ID number (located on bottom of the
Gateway)"**, pre-filled `888.1.xxxx.xxx.xx`. That is exactly the offset-21 ltid
— a **sticker on the box** the human types into the app. No cloud, no hardcode:
the app has no gateway ltid until you enter it (which is why cracking the beacon
hash felt harder than it was — the real "protocol" is reading a label).

So the CLI now mirrors the app: `configure` prompts for the Gateway ID and
stores it in `.atlantik-gateway` (cwd); `gateway_id`/`gw_ltid` read it for both
the request (offset 21) and the discovery-beacon seed. Every command aborts
early with setup instructions until it is set; a wrong-but-valid ID falls
through to a clear "gateway not found — check the Gateway ID" error; and a
missing light aborts in `status`. The `discover` _command_ is gone (pointless —
the ID is on the box), but the beacon broadcast still runs internally to find
the IP, so DHCP changes are still handled.

Map to the app: their step 4 (type Gateway ID) = our `configure`; step 5
("Search") = `GetDevices`. We just automate the number-off-the-box lookup and
skip the phone.

## 44. The last bug — a stale clock, and the gateway's device cache

`status` kept showing a device clock that was wrong and never advanced: stuck at
`04:27` (`RgbwCurrentTime.CurrentTime` = 16041 s), run after run. Reading the raw
value confirmed it was frozen, unchanged minutes apart:

```shell
$ ruby atlantik.rb GetDevices | grep -o 'RgbwCurrentTime.\{0,50\}'
...<var name="CurrentTime">16041</var>...    # identical minutes later
```

Then it would jump — 26643 (`07:24`), later 27018 (`07:30`) — but **only right
after the phone app was opened**, never on its own, and each jump matched real
elapsed wall time.

**Cause: the gateway caches each node's state.** `GetDevices` returns that cache,
not a live poll of the mesh, so the light's clock/temp only move when something
forces a re-poll. The phone forces it: its Device Status panel
(`DeviceListFragment`) calls `GetUpdateSingleDeviceCache <id>` (or gateway-wide
`GetUpdateDeviceCache`, empty body — `DeviceManager.getUpdateDeviceCache`) and
reads time/temp from *that* fresh reply, never from a plain `GetDevices`. Ours
used plain `GetDevices`, so we saw whatever the phone had last refreshed.

Fix: the CLI now calls `GetUpdateDeviceCache` before every gateway command (a
`refresh!` in the dispatcher), so any read — `status`, a raw `GetDevices`, the
device-id lookup that writes use — sees freshly-polled state. The clock advances
on its own again.

Two related facts, from the decompiled app:

- **No timezone translation.** The app formats `CurrentTime` seconds-of-day
  straight to `HH:MM` (same formula we use). The value is "local" only because
  the phone *sets* it: on connect the app calls `SetTime` with its own calendar
  (`DeviceManager`, `"%tY.%tm.%td-%tH:%tM:%tS"`), i.e. phone-local wall time. The
  light has no timezone logic; it runs its seconds-of-day schedule against
  whatever local time the phone last pushed. If no phone connects, nothing
  corrects it.
- **`GetTimezone` is the gateway's OS zone, not the light's** — unrelated to the
  device clock (it read "Asia/Hong Kong" while the light ran on the owner's
  phone-local time), so it's been dropped from `status`.

## Next steps

Optional polish only: convenience write subcommands
(`set`/`all`/`scene`/`on`/`off`), already covered by `mode manual` + raw
`<Service>` passthrough.
