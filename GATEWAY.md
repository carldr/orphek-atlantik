# Orphek Gateway — system reference

Incidental system-level notes on the Orphek gateway box, gathered over SSH while
reverse-engineering the light protocol (see [FINDINGS.md](FINDINGS.md) for the
protocol work). Root via `snap` (§11a of FINDINGS). Live IP is DHCP — currently
`192.168.2.62` (was `.98`); find it with `ruby atlantik.rb discover`.

## Hardware
- **SoC:** Atheros AR9330 rev 1 (AP121 reference board) — MIPS 24Kc V7.4, single
  core, ~265 BogoMIPS. This is a cheap 2.4 GHz WiFi-router SoC repurposed.
- **RAM:** 64 MB (`MemTotal` 61,512 kB; ~33 MB free).
- **Flash:** ~8 MB SPI NOR, laid out for A/B (dual-image) OTA:

  | mtd | size | name |
  |-----|------|------|
  | 0 | 256K | u-boot |
  | 1 | 64K | u-boot-env |
  | 2 | 4.75M | rootfs1 (alt) |
  | 4 | 1M | uImage1 (alt) |
  | 5 | 1M | uImage (active) |
  | 6 | 7.06M | rootfs (active, squashfs) |
  | 3,7 | 448K,1.3M | rootfs_data (overlay) |
  | 8,9 | 64K each | NVRAM, ART (wifi cal) |

  Active root is a read-only squashfs (`/rom`, full) + a tiny JFFS2 overlay
  (`/overlay`, ~930 KB free) — very little writable space.

## OS
- **OpenWrt “Attitude Adjustment” 12.09.1** (r40431), rebranded
  `DISTRIB_ID="NXP IoT Gateway (exported)"`, kernel **Linux 3.3.8**, target
  `ar71xx/generic`. Ancient (2013-era) — old dropbear/crypto (§12).
- Load average steady ~**1.0** (one core ~pegged). Profiled to a single
  `longtooth_test` worker **thread busy-spinning in pure userspace — zero
  syscalls, no poll/sleep/yield** (of its 15 threads, one is state `R` with
  `utime` climbing ~82%/core; `/proc/<tid>/syscall` empty). It's a C++
  `std::thread`; given the daemon's `event_queue`/`obj_q` structures it's almost
  certainly a work-queue consumer that busy-polls instead of blocking on a
  condvar. **Not** the cloud connect (that thread blocks and times out ~every 30s;
  errno 145 = `ETIMEDOUT` on MIPS). So blackholing the cloud IP wouldn't help.
  Unfixable without patching the binary (add a yield) — harmless, just wasteful.

## Network
- **eth1** = the only active uplink: DHCP client on the LAN,
  `192.168.2.62/23` (mask 255.255.254.0), MAC `04:BA:36:00:51:92`.
- **br-lan/eth0** (MAC `70:B3:D5:…`) — bridge, unused here.
- **zb0** — the ZigBee/JenNet-IP interface (802.15.4 via the JN5168).
- IPv6 ULA `fd04:bd3:80e8::/48`; the JenNet-IP light network lives at
  `fd04:bd3:80e8:10::/64` (border router `::1`).

## Daemons / listening ports
| Proto/Port | Process | Purpose |
|---|---|---|
| tcp 22 | dropbear | SSH (root enabled) |
| tcp 80 / 443 | uhttpd | Web UI (LuCI + JIP.cgi), self-signed cert |
| tcp/udp 53, udp 67 | dnsmasq | DNS/DHCP |
| tcp 127.0.0.1:1880 | zigbee-jip-daemon | local IPC |
| udp [::]:1873 | zigbee-jip-daemon | **JIP** (JenNet-IP control) |
| udp 1874 | FWDistributiond | NXP firmware distribution |
| udp 30500 / 43100 / [::]:42388 | **longtooth_test** | the app/CLI control protocol |
| udp 1812/1813 | radiusd | 802.15.4 join auth (RADIUS) |
| udp 5353 | avahi | mDNS |
| udp 546/547 | odhcp6c / 6relayd | DHCPv6 / RA relay |

Other daemons: `crond` (no jobs installed), watchdog.

## Web UI (ports 80/443)
- `uhttpd`, home `/www`, cgi at `/cgi-bin`, https via self-signed
  `/etc/uhttpd.crt` (px5g-generated).
- `/www/index.html` just redirects to **`/cgi-bin/luci`** — the standard OpenWrt
  **LuCI** admin (login = root / `snap`).
- **`/cgi-bin/JIP.cgi`** — a CGI exposing **JenNet-IP over HTTP**: a third
  light-control path (besides LongTooth UDP 30500 and SSH+`JIP`). `Browser.html`
  / `SmartDevices.html` are its front-ends.

**External exposure:** uhttpd binds `0.0.0.0` and the firewall `INPUT` policy is
`ACCEPT` (wide open — see below), so the web UI + SSH are reachable from anywhere
on the LAN. Not internet-facing unless the upstream router (OPNsense)
forwards a port to it — by default it is behind NAT and not exposed to the
internet.

**⚠ LuCI = full root over HTTP.** LuCI is the stock OpenWrt admin, so anyone on
the LAN who logs in (root / `snap`) has complete control of the box — it exposes
a *lot* of device info and enough control to brick our tooling or the light.
Things that break control if changed there:

- **Change root password / disable dropbear (SSH)** — kills our `sshpass -p snap`
  access and the `scratchpad/gw*` helpers (the LongTooth CLI still works — it
  needs no root). If you change the password, note the new one.
- **Disable startup scripts** — light control is launched by `/root/set_config.sh`
  (`S99zz_config` → runs `longtooth_test`, RTC sync, `chkzigbee`, `check_*`).
  Disabling it stops both the app and our CLI from reaching the light until
  re-enabled/rebooted. (The bulb keeps running its stored schedule regardless.)
- **Remove packages / edit configs** — risky on ~930 KB free flash; could break
  `uhttpd`, `dropbear`, `dnsmasq`, or the JIP/LongTooth stack.
- **Do NOT kill `longtooth_test`** — it's the control bridge (it's also the
  steady ~1.0 load, from its cloud-retry loop; that's normal here).

This is itself a security finding: a wide-open LAN box (firewall `INPUT ACCEPT`,
plaintext creds, web root, old unpatched OpenWrt) — safe only because it sits
behind the router's NAT.

## Cloud / remote access
- The gateway continuously tries to reach its cloud relay
  **`register.longtooth.io` (`47.91.142.68:53199`)** and fails (`SYN_SENT`) —
  so Orphek's remote-from-anywhere access is effectively dead here. Local control
  (our CLI, JIP, LuCI) is unaffected.
- Push notifications: `/root/curl` POSTs to **`push.hotechie.com:8001`**.

## `gateway_cache.db` (SQLite at /root) — the home-automation data model
A full smart-home schema the gateway maintains (the app reads/writes it via the
Get*/Set* services). Live counts: Device 4, Program 2, User 2, Groups 1,
MibVar 58, others 0. Tables:

- **Device**(device_id) · **MibVar**(device_id, mib, var, val) — a **cached copy
  of every device's MiB variables** (channel levels, temp, curves…), readable
  directly over SSH as an alternative to LongTooth.
- **Program**(program_id, name) · **Program_Command**(program_id, device_id, mib,
  var, val) — the stored day schedules (RgbwCurves).
- **Scene**/**Scene_Command**/**SceneTrigger**(+_Weekday) — scenes and their
  schedule triggers.
- **Rule**/**Rule_Trigger**/**Rule_Action**/**Rule_Timer**/**Rule_Restore**/
  **Action_Command**/**Restore_Command** — an if-this-then-that automation engine
  (trigger on a device var condition → run actions → optionally restore).
- **ExternalSceneTrigger**(+_Weekday) — sunrise/scheduled scene triggers.
- **Groups**/**Groups_Device**, **Room**/**Room_Device** — grouping.
- **User**(name, role, **password** [plaintext], ltid) ·
  **User_PushToken**(user_name, app_id, token) — accounts + push registration.
- **Icon**(icon_id, data), **Metadata**(key, value).

## Security notes
- Root SSH enabled, password `snap` (MD5-crypt, cracked). LuCI uses the same.
- App/DB credentials stored **in plaintext**: `admin/admin`,
  `administrator/administrator`.
- **Firewall `INPUT` policy = ACCEPT** (the S99iptable script only *adds* ACCEPT
  rules and never sets a DROP policy — and has run several times, so the rules
  are duplicated). The box is effectively unfirewalled on its LAN interface.
- HTTPS is a self-signed cert. Old OpenWrt 12.09 / kernel 3.3.8 — unpatched.
- Net: fine behind the NAT/LAN; would be alarming if directly internet-exposed.

## Architecture (how a command reaches the light)
```
 phone app / atlantik.rb ── UDP 30500 "LongTooth" ─┐
 LuCI / JIP.cgi ──────────── HTTP :80/:443 ─────────┤
 SSH + JIP ───────────────── local ────────────────┤
                                                    ▼
                                          longtooth_test / zigbee-jip-daemon
                                                    │  (JenNet-IP over 802.15.4)
                                                    ▼
                                   Atlantik v4 RGBW bulb (fd04:bd3:80e8:10:…:27d:2a28)
 (register.longtooth.io = optional cloud rendezvous for remote apps — currently down)
```
Almost all state (curves, scenes, rules, cached MiB values) lives on the gateway
or the bulb; clients just read/write MiB variables — which is why a small script
matches the app's capabilities.
