# JenNet-IP network map — live gateway (192.168.2.98)

Captured via `JIP -6 fd04:bd3:80e8:10::1 -e "discover;print"` (root SSH).
Border router / coordinator address: `fd04:bd3:80e8:10::1`. 4 nodes.

Full verbatim `print` output: [`jip-discover-print.txt`](jip-discover-print.txt)
(891 lines). This file is the distilled map. `?` values = not read in the
discovery pass (structure only).

## Nodes

| IPv6 address                            | DeviceID         | MAC                       | Role                                                                                      |
| --------------------------------------- | ---------------- | ------------------------- | ----------------------------------------------------------------------------------------- |
| `fd04:bd3:80e8:10::1`                   | `0x08010001`     | —                         | Border router / gateway coordinator node                                                  |
| `fd04:bd3:80e8:10:15:8d00:389:6707`     | `0x08010010`     | `00:15:8d:00:03:89:67:07` | ZigBee **ControlBridge** (coordinator radio) — PermitJoining/Touchlink/RemoveNode         |
| `fd04:bd3:80e8:10:17:8801:b24:2e04`     | `0x08011175`     | `00:17:88:01:0b:24:2e:04` | Mono **BulbControl** node (no Rgbw MiBs) — 2nd luminaire or repeater; not the Atlantik v4 |
| **`fd04:bd3:80e8:10:15:8d00:27d:2a28`** | **`0x6ec70001`** | `00:15:8d:00:02:7d:2a:28` | **Atlantik v4 RGBW light** (target)                                                       |

`0x6ec7…` is Orphek's manufacturer prefix (also on `Alarm` MiB 0x6ec71000 and
all `Rgbw*` MiBs). Node1's `JenNet:NetworkTable` lists the 3 children, matching
the MACs above.

## Atlantik v4 (node `…27d:2a28`) — control surface

### `RgbwBulbControl` (MiB ID `0x6ec70008`) — the main dimmer

| Var            | Index | Type  | Access |
| -------------- | ----- | ----- | ------ |
| RedMode        | 0     | UINT8 | RW     |
| GreenMode      | 1     | UINT8 | RW     |
| BlueMode       | 2     | UINT8 | RW     |
| WhiteMode      | 3     | UINT8 | RW     |
| RedLumTarget   | 4     | UINT8 | RW     |
| GreenLumTarget | 5     | UINT8 | RW     |
| BlueLumTarget  | 6     | UINT8 | RW     |
| WhiteLumTarget | 7     | UINT8 | RW     |

`LumTarget` = per-channel intensity (UINT8; range 0–255 or 0–100 — TBD by read).
`*Mode` = per-channel mode (manual vs curve/auto — TBD).

### Other Orphek MiBs on this node

- `RgbwCurves` (0x6ec70009) — per-channel `*Curve0`/`*Curve1` BLOBs (daily curves)
- `RgbwClouds` (0x6ec70010) — `CloudMode` (U8), `CloudTime` (BLOB)
- `RgbwTemperature` (0x6ec70011) — `Temperature` FLT, read-only (heatsink)
- `RgbwWorkMode` (0x6ec70012) — per-channel `*Mode` (U8) — duplicate of the Mode set
- `RgbwCurrentTime` (0x6ec70013) — `CurrentTime` UINT32 (epoch clock)
- `RgbwDemoMode` (0x6ec70014) — `Time`, `MaxLevel`, `StartDemo` (U8)
- Generic bulb MiBs also present: `BulbControl` (0xfffffe04: Mode/SceneId/
  LumTarget/LumCurrent/LumChange/LumCadence/LumCadTimer), `BulbScene`
  (0xfffffe03), `BulbStatus` (0xfffffe00: OnCount/OnTime/ChipTemp/BusVolts),
  `DeviceControl` (0xfffffea2: Mode/SceneId), `Alarm` (0x6ec71000: Blinking/Fadein)
- Infra MiBs: `NodeStatus`, `NodeControl` (Reset/FactoryReset), `NwkStatus`,
  `NwkSecurity` (Channel/PanId), `Groups`, `OND`, `DeviceID`, `Node`

## JIP command grammar (from binary help)

`JIP -6 <borderrouter> -e "cmd;cmd;…"` — commands `;`-separated. Selectors:

- `device <DeviceID>` — set active device (e.g. `device 0x6ec70001` = the light)
- `<IPv6 address>` — set active node address
- `mib <name|id>` / `var <name|index>` — select MiB / variable
- `get` — read active variable · `set <value>` — write it
- `print` — dump discovered network · `discover` — run discovery

Expected control write (per-channel intensity):

```
JIP -6 fd04:bd3:80e8:10::1 -e "discover;device 0x6ec70001;mib RgbwBulbControl;var WhiteLumTarget;set <0-255>"
```

Only node `…27d:2a28` exposes `RgbwBulbControl`, so selecting that MiB is
unambiguous for the RGBW light even without the `device` selector — TBD which
addressing JIP actually requires (confirm with a `get` first).
