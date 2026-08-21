# OrphekHack

Controlling an **Orphek Atlantik v4** reef light from the command line, with no
phone app and no root. This was achieved by reverse-engineering the "LongTooth"
protocol its gateway speaks.

- **`atlantik.rb`**: the CLI. After a one-time `configure` (enter the Gateway ID
  printed on the box), `ruby atlantik.rb` gives you `status`, `programs`, `mode
  manual|demo|program`, and raw `<Service>` calls. It then broadcast-finds the
  gateway, so it survives DHCP changes. Reads need nothing, writes move the light.
- **[FINDINGS.md](FINDINGS.md)**: the full chronological reverse-engineering
  log. This includes protocol decode, Ghidra work, dead-ends and all.
- **[GATEWAY.md](GATEWAY.md)**: incidental system notes on the gateway box.
  These cover hardware, daemons, SQLite schema, web UI, and security.

The blow-by-blow, including every dead end in the order I hit it, is in
[FINDINGS.md](FINDINGS.md).

And the whole of this was achieved using Anthropic's Opus 5, over the course
of a few hours while working on other projects.

## atlantik.rb

```shell
❯ ruby atlantik.rb configure
Gateway ID (on the bottom of the gateway, e.g. 888.1.xxxx.xx.xx): 888.1.23xx.xx.xx
saved Gateway ID 888.1.23xx.xx.xx to .atlantik-gateway

❯ ruby atlantik.rb status
  Orphek Atlantik v4   [192.168.2.62]  id 888.1.23xx.xx.xx  fw version 0.8692 A
  time 04:27 (Asia/Hong Kong)   temp 26.3°C
  channels now:
    Red    [····················]   0
    Green  [····················]   0
    Blue   [····················]   0
    White  [····················]   0
  day schedule loaded (00→23h):
    Red              ▁▂▂▃▃▃▄▄        00:00=0% 09:00=1% 12:00=30% 17:00=50% 18:00=0%
    Green           ▁▂▃▄▄▄▄▅▅▄▂      00:00=0% 08:00=1% 12:00=50% 17:30=60% 20:00=0%
    Blue             ▁▂▂▂▂▂▂▂        00:00=0% 09:00=1% 12:00=30% 17:00=30% 18:00=0%
    White            ▁▂▂▃▃▃▄▄▂       00:00=0% 09:00=1% 12:00=30% 17:00=50% 19:00=0%
```

```shell
❯ ruby atlantik.rb
Orphek Atlantik v4 CLI

Run `configure` once to set your Gateway ID.

READ commands (safe any time):
  status              live snapshot: gateway IP + firmware, device clock &
                      timezone, heatsink temp, current per-channel levels
                      (0-255, flagged MANUAL if overridden), and the day
                      schedule currently loaded on the light (24h sparkline
                      + key time/intensity points per R/G/B/W channel).
  programs            every program STORED on the gateway, decoded the same
                      way as the schedule in `status`.
  configure           store your Gateway ID (the 888.1.… number on the
                      underside of the gateway) in .atlantik-gateway. Run
                      this once before anything else.
  <Service> [body]    call any gateway service directly (full list below).
                      e.g. `GetTimezone`, `GetUsers`, `GetChannel`. A few
                      take an argument as [body], e.g. `GetUser admin`.
  help                this text (also shown with no arguments).

WRITE commands (move the light — use in daylight; prefix DRY_RUN=1 to preview
the exact writes without sending anything):
  mode manual <r> <g> <b> <w>
                      hold each channel at a fixed level. 4 integers, one
                      per channel Red/Green/Blue/White, each 0-255 (clamped).
                      This overrides the schedule for those channels until
                      you run `mode program`.
  mode demo [max%] [secs]
                      run the light's built-in RGBW demo cycle (on-device,
                      not an app animation). max% = peak brightness 10-100
                      (default 100); secs = how long the demo runs, 1-300
                      (default 60). Stop early with `mode program`.
  mode program        hand every channel back to its loaded schedule (sets
                      RgbwWorkMode=0) and stops any running demo. Undoes
                      `mode manual` / `mode demo`. Curves stay on the device,
                      so it resumes at the current time of day.

Env:  GW=<ip>   skip discovery and target this gateway IP.
      DRY_RUN=1  print writes instead of sending them.

All gateway services (Get* = read-only/safe; Set*/Add*/Delete*/Reset* write):
  AddUser                     AllowAddDevice              DeleteExternalSceneTrigger
  DeleteGroup                 DeleteOnOffScene            DeleteProgram
  DeleteRoom                  DeleteRule                  DeleteScene
  DeleteUser                  GetCapabilities             GetChannel
  GetDevices                  GetDevicesByGroup           GetDevicesByRoom
  GetExternalSceneTriggers    GetGatewayVersion           GetGroups
  GetIcons                    GetPrograms                 GetRecords
  GetRoomByDevice             GetRooms                    GetRuleDetail
  GetRuleList                 GetRuleListDetail           GetScenes
  GetSystemPara               GetTimezone                 GetUpdateBuildVersion
  GetUpdateDeviceCache        GetUpdateFirmware           GetUpdateSingleDeviceCache
  GetUser                     GetUsers                    GetWifis
  LoginUser                   RefreshCache                RemoveDevice
  ResetGateway                SetAllowNewDevices          SetBatchMibVar
  SetBatchMibVarByGroup       SetChannel                  SetExternalSceneTrigger
  SetExternalSceneTriggers    SetGroup                    SetIcon
  SetMibVar                   SetMibVarByGroup            SetOnOffScene
  SetOnOffSceneName           SetProgram                  SetRoom
  SetRule                     SetScene                    SetSystemPara
  SetTime                     SetTimezone                 SetUser
  SetWifi                     TestThroughput              lttest
```

## Reverse-engineering my reef light

I own a reef light. It's a fantastic piece of hardware, specifically an Orphek
Atlantik v4 featuring four channels of LEDs over a tank of coral. But the only
way to talk to it is a phone app. You tap a slider, and the light changes.
That's fine, until the day you want the light to do something the app doesn't
offer. Maybe you want to fade on a schedule you wrote, react to something else
in the house, or just be pokeable from a script. The app is a locked door in
front of a device I paid for.

So I decided to pick the lock. I had no documentation, no source code, and no
vendor help. I just had the light, a laptop, and the tools already on it. What
follows is how far that gets you. Spoiler alert: it gets you all the way. If
you've ever looked at a gadget in your house and wondered what it's really
saying on the wire, this is an invitation.

### First surprise: the firmware isn't the light

The only inputs I gave myself were the vendor's own public downloads. This was a
pile of Android APKs and a gateway firmware image, all sitting on `orphek.com`
for anyone to grab. No leak, no insider. Just stuff already on the open web.

The firmware was the first plot twist. I expected the light's brain. Instead, I
got an **OpenWrt router**. It turns out the Atlantik v4 has no WiFi at all. It's
actually a radio node speaking 802.15.4 on the ZigBee band, and a separate
little **gateway box** bridges it to your LAN. Crack open that firmware and it's
stock OpenWrt plus NXP's JenNet-IP middleware. The light itself is a boring,
standard mesh bulb. It's basically a bag of named variables like red level,
white level, temperature, and the daily curve. All the personality lives in the
gateway.

That reframed the whole thing. I wasn't hacking a light. I was hacking a tiny
Linux router, and the light was just the thing on the far end of it. This made
it much less intimidating. This is the first lesson of poking at consumer
hardware: it's almost always a Linux box you already know how to reason about,
wearing a costume.

### Two ways in: the cheat and the real game

Reading the firmware turned up two routes to the light, and I ended up chasing
both for different reasons.

**The cheat: SSH in and use the tool that's already there.** The gateway ships
NXP's stock `JIP` command-line tool. This tool does exactly what I wanted by
letting me read and write the bulb's variables from a shell. If I could log in,
I was basically done. The catch was finding the root password. The firmware
image had a default password hash, but it didn't match the live box since
someone had changed it at the factory. So I fed the live hash to John the Ripper
and the rockyou wordlist and let it run. It fell out in seconds: **`snap`**. The
firmware's default was a decoy, and the real one was set at provisioning. Always
test against the live device!

That gave me full root and, more importantly, **ground truth**. With `JIP` I
could read the light's real state any time and check my work against it. This
mattered because the cheat wasn't the point.

**The real game: speak the app's own protocol, no root required.** Anyone with
the app controls this light without logging into anything. I wanted to do the
same and reproduce the protocol the app speaks. This would mean a plain script
on the LAN could drive the light with no shell, no password, and no cloud.
That's the version of this worth bragging about. Everything from here is that
path.

### Cracking it open: it's just XML

Strings in the app pointed at a hand-rolled UDP protocol under the namespace
`xpod.longtooth`. It wasn't HTTP, nor REST, but something custom and binary.
That sounds scary, but it really wasn't.

I ran `tcpdump` on the gateway while I flicked sliders in the app. The captured
packets gave up the best possible news: **the payloads are plaintext XML.**
There is no encryption on the local network at all. The app carries RSA key
material, but that's only for phoning home to the cloud relay. The LAN path is
wide open. A command to the light is literally readable:

```xml
<command><device>…</device><mib>RgbwBulbControl</mib>
        <var>WhiteLumTarget</var><val>128</val></command>
```

That's the whole secret of "set white to 128." The moment you see your own
slider drag turn into legible text on the wire, you're hooked. There's nothing
left to break, only something to reproduce.

### The binary wrapper, and one detail that mattered

The XML rides inside a small binary frame, and to send my own I had to
understand it. I pulled the app apart with jadx and read its serializer
directly. It turned out to be a length prefix, a couple of address fields, a
connection id, an opcode and a flag, then the length-prefixed service name and
body. It's little-endian throughout.

Transport is a tidy two-tunnel handshake. The client opens a request tunnel. The
gateway acks it and opens a *reverse* tunnel to stream the answer back. The
client says "go" and the reply arrives across a few data frames before the
client closes. The one detail that turned "nothing works" into "it works" was
the reverse-tunnel id. It's the **two's-complement negation of the request id**.
Get that wrong and the gateway just never answers. Get it right and, in a small
Ruby client, `GetDevices` comes back with the live device XML. That was the
first real reply driven entirely by my own code. That's the good part of this
hobby. It's the moment the machine talks back.

### The wall: when the gateway went quiet, and I blamed everything but myself

Then reads got flaky. This is the part I want to be honest about, because
reverse-engineering is mostly this. The gateway would ack my request and then
simply not send the answer. Sometimes, but not always. And I misdiagnosed it,
repeatedly and confidently.

- I decided the gateway had *crashed* from a memory leak. It hadn't. Its uptime
  was fine. Its **DHCP lease had just moved it to a new IP** and I was talking
  to an empty address.
- I decided it needed a reboot. It didn't. My own **discovery beacon** was
  wedging it, by kicking off a peer-registration that blocked on the dead cloud
  relay.
- I decided, twice, that the gateway was the problem. It never was. Meanwhile
  another phone in the house connected and read the light perfectly. That should
  have told me sooner: the box was healthy the whole time. The bug was mine. I
  was reusing one client id across interrupted reads and leaving half-open
  tunnels behind.

Every one of those was a dead end I was sure about at the time. None of them
made the final cut except as a lesson. If you take up this kind of work, get
comfortable being wrong out loud. The device is a fixed point of truth, and your
job is to stop being wrong faster.

### Ghidra, and the actual answer

The real cause needed the big tool. I loaded the gateway's `longtooth_test`
binary, a stripped MIPS file with no symbols, into Ghidra and read the
decompiled routing logic. There it was: the reply is delivered to a "member"
record keyed by the **source id in the request**. The app registers a per-user
id at login and binds it to that phone's address. By borrowing the app's admin
id, I'd been politely asking the gateway to send *my* answers to *the phone*.

The fix was almost funny after all that. I just needed to send a **unique id of
my own**. The gateway makes a fresh member bound to my machine's address, and
the replies come straight home. They were reliable every time, phone on or off,
no root, and no app. Reads were solved. And I did it by decompiling the vendor's
own binary and doing exactly what it expected, just as myself instead of as the
phone.

Writes, it turned out, were never the problem. The gateway executes a command
the instant it arrives without needing a reply, so `SetMibVar` works as
fire-and-forget. I confirmed a channel change end-to-end by reading the value
back through `JIP`. The cheat path finally earned its keep as a referee.

### Then I read the manual

One value stayed stubbornly hardcoded: the gateway's *own* id, the twelve bytes
at the front of every request. The gateway checks it to be sure I mean *it*, and
the discovery beacon hashes it too — I proved that when a beacon carrying the
wrong id got nothing but silence. So how does a client that's never met this
gateway learn that id? I chased it hard. I decompiled the beacon logic, worked
out the hash, and even discovered the gateway quietly serves its own id at
`http://<gateway>/longtoothID` — so I could fetch it automatically. I was quite
pleased with myself.

Then, almost as an afterthought, I opened the official setup guide. Step 4:
*"Enter the Gateway ID number (located on the bottom of the Gateway)."* The
number I'd been cracking out of packet hashes and scraping off a hidden web
endpoint is **printed on a sticker on the underside of the box.** The app doesn't
discover it either — it asks you to type it in. The grand mystery of "how does
the client know the gateway's id" had a two-word answer: it doesn't. A human
reads the label.

So the tool now does the honest thing, exactly like the app: `configure` asks for
that number once and remembers it. And the real reverse-engineering lesson is the
one I keep re-learning: read the manual. Not first — half the fun is *not*
knowing, and I'd have skipped the best parts — but read it. The device's own
documentation is a primary source, and sometimes the secret you're painstakingly
extracting from firmware is stuck to the bottom of the case in plain sight.

### What you get for all that

Once the protocol was mine, the light's own features fell out for free. The
daily schedule is stored as `RgbwCurves` blobs, lists of `[intensity,
seconds-of-day]` points, which decode into the actual sunrise-to-dusk curve
loaded on the bulb. Manual control and handing it back to the schedule are just
two more variables. Even the demo light-show runs on the bulb itself. You only
have to flip a flag.

The result is **`atlantik.rb`**: a dependency-free Ruby CLI that reads live
state like the clock, temperature, per-channel levels, and the loaded and stored
schedules. It also changes channels, switches between manual, demo, and program
modes, and finds the gateway by broadcast so a DHCP move doesn't break it. This
is all over the LAN, no root, and no phone. It works because, underneath, it
does precisely what the app does by reading and writing variables on a mesh
device through a gateway. The app was never magic. It was just the only one
holding the key.

### The point

None of this needed anything exotic. The inputs were public downloads. The tools
are all free and mostly already installed: `tcpdump`, jadx, John the Ripper,
Ghidra, and a bit of Ruby. The device fought back exactly as much as any real
target does. It fought with silence, red herrings, and a couple of days of me
being confidently wrong. And it still gave everything up.

If there's a gadget in your house that only obeys its own app, that's not a
wall. It's a weekend. Go read its packets.
