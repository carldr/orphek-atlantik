#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Minimal LongTooth LAN client for the Orphek gateway (UDP 30500) — no root,
# no app. Frame format reverse-engineered from the app's own serializer
# (xpod.longtooth b.java/w.java) + Ghidra RE of longtooth_test; see FINDINGS.md
#
#   ruby atlantik.rb GetDevices
#   DEBUG=1 ruby atlantik.rb GetDevices
#
# Frame:  [len:4 LE = size-2][addr1:6=0][addr2:6=0][connid:4 LE][op][flag][b3]
# Request (op=04 flag=01): + [gwLtid:12 @21][userLtid:12 @33 UNIQUE][respConnid:4 = -connid]
#                          + [0:4][dataType:1][svcLen:1][svc][bodyLen:4 LE][body]

require "socket"

module LongTooth
  PORT = 30_500

  module_function

  # Resolve the gateway IP: use $GW if set, else broadcast-discover it (survives
  # the gateway getting a new DHCP IP). Memoised per process.
  def gateway
    @gateway ||= ENV["GW"] || discover(2).keys.first || abort(
      "gateway not found on :30500 — check it is powered and on this LAN, and " \
      "that the Gateway ID (#{gateway_id}) is correct (re-run `configure`)")
  end

  # The configured Gateway ID — the "888.1.…" number printed on the underside of
  # the gateway, entered via `configure` (exactly what the app asks for in setup
  # step 4). It is the ltid at request offset 21 AND the seed the discovery
  # beacon hashes, so nothing talks to the gateway until it is set. (§43)
  CONFIG_FILE = ".atlantik-gateway"

  def gateway_id
    @gateway_id ||= (File.read(CONFIG_FILE).strip if File.exist?(CONFIG_FILE))
  end

  # The Gateway ID as 12 raw bytes (request offset 21). Aborts if unconfigured.
  def gw_ltid
    @gw_ltid ||= ltid(configured!)
  end

  # Return the configured Gateway ID, or abort early with setup instructions.
  def configured!
    id = gateway_id
    return id if id&.match?(/\A\d+(\.\d+){4}\z/)
    abort "not configured — run `ruby #{$0} configure` and enter the Gateway ID " \
          "(the 888.1.… number printed on the bottom of the gateway)"
  end

  # Prompt for the Gateway ID and store it in .atlantik-gateway (current dir).
  def configure
    print "Gateway ID (on the bottom of the gateway, e.g. 888.1.xxxx.xx.xx): "
    id = ($stdin.gets || "").strip
    abort "not a valid Gateway ID: #{id.inspect}" unless id.match?(/\A\d+(\.\d+){4}\z/)
    File.write(CONFIG_FILE, id + "\n")
    puts "saved Gateway ID #{id} to #{CONFIG_FILE}"
  end


  # Our client "member" id (request offset 33). The gateway keys the response
  # tunnel on it, so it must be UNIQUE to us — NOT admin's 1.1.544.980.957, which
  # belongs to the phone (reusing it routes our replies there). Fresh random per
  # process: a stable id backfires — if its member gets a stuck/half-open tunnel
  # from an interrupted read, every later read on it fails; a fresh id always
  # gets a clean member. (§34/§39, Ghidra RE of the offset-33 routing.)
  USER_LTID = [1, 1, rand(0x1000_0000..0x3FFF_FFFF)].pack("V3")

  GO_TRAILER = ["0000000101010101010101"].pack("H*")

  module_function

  # Pack an "A.B.C.D.E" ltid into 12 bytes (w.a(k): a, b, (C<<20)|(D<<10)|E).
  def ltid(str)
    a, b, c, d, e = str.split(".").map(&:to_i)
    [a, b, (c << 20) | (d << 10) | e].pack("l<3")
  end

  def u32(int) = [int & 0xFFFF_FFFF].pack("V")

  # w.b: rolling ×31 hash over signed bytes, 32-bit wrap.
  def hash31(bytes)
    h = 0
    bytes.each_byte { |b| h = (h * 31 + (b > 127 ? b - 256 : b)) & 0xFFFF_FFFF }
    h
  end

  # Discovery beacon (op 09). base(54,…) + nonce@21 + hash31(nonce||gwLtid)@29;
  # the gateway validates that hash against its OWN ltid, so the Gateway ID must
  # be configured before discovery can find the box. (§43)
  def beacon(connid, nonce)
    ident = [nonce].pack("Q<") + gw_ltid      # 8 + 12 bytes, hashed below
    buf = base(54, connid, 0x09, 0x02, 0x01)
    buf[21, 8] = [nonce].pack("Q<")
    buf[29, 4] = u32(hash31(ident))
    buf
  end

  # Base frame shared by every packet type.
  def base(size, connid, op, flag, b3)
    buf = ("\x00" * size).b
    buf[0, 4]  = u32(size - 2)   # length (addr fields are zero, no overlap)
    buf[14, 4] = u32(connid)
    buf.setbyte(18, op)
    buf.setbyte(19, flag)
    buf.setbyte(20, b3)
    buf
  end

  def request(connid, service, body)
    size = service.bytesize + 55 + 4 + body.bytesize
    buf = base(size, connid, 0x04, 0x01, 0x01)
    buf[21, 12] = gw_ltid
    buf[33, 12] = USER_LTID
    buf[45, 4]  = u32(-connid)                 # response connid = -request connid
    buf.setbyte(53, 0)                         # dataType
    buf.setbyte(54, service.bytesize)
    buf[55, service.bytesize] = service.b
    off = 55 + service.bytesize
    buf[off, 4] = u32(body.bytesize)
    buf[off + 4, body.bytesize] = body.b
    buf
  end

  def debug(dir, pkt)
    return unless ENV["DEBUG"]
    warn format("  %-4s connid=%08x op=%02x flag=%02x len=%-4d %s", dir,
                pkt[14, 4].unpack1("V"), pkt.getbyte(18), pkt.getbyte(19),
                pkt.bytesize, (pkt[24..] || "").gsub(/[^\x20-\x7e]/, ".")[0, 40])
  end

  def call(service, body = "empty")
    connid   = rand(0x4000_0000..0x7FFF_FFFF)  # fresh request tunnel id each run
    resp     = (-connid) & 0xFFFF_FFFF         # gateway's response tunnel id (= -connid)
    gw = gateway                               # resolve BEFORE binding (discover also binds :30500)
    socket   = UDPSocket.new
    socket.bind("0.0.0.0", PORT)
    send = ->(frame) { debug("send", frame); socket.send(frame, 0, gw, PORT) }

    # NB: do NOT send a discovery beacon (op 09) here — it makes the gateway
    # attempt a peer-registration that blocks on the dead cloud relay and wedges
    # its request handler. The request alone is enough. (§38)
    req = request(connid, service, body)
    send.call(req)

    chunks     = {}
    got_resp   = false
    deadline   = Time.now + 5
    next_retry = Time.now + 0.4
    loop do
      now = Time.now
      break if now >= deadline
      if !got_resp && now >= next_retry
        send.call(req)
        next_retry = now + 0.4
      end
      wait = [next_retry, deadline].min - now
      next unless wait.positive? && IO.select([socket], nil, nil, wait)

      pkt, = socket.recvfrom(8192)
      debug("recv", pkt)
      cid = pkt[14, 4].unpack1("V")
      next unless [connid, resp].include?(cid)
      op, flag = pkt.getbyte(18), pkt.getbyte(19)

      if op == 0x04 && flag == 0x02          # gateway opened the response tunnel
        got_resp = true
        send.call(base(21, resp, 0x04, 0xfe, 0x01))   # ack it
        send.call(base(31, resp, 0x07, 0x00, 0x00).tap { |f| f[20, 11] = GO_TRAILER }) # go
      elsif op == 0x06                       # data
        data = pkt[24..] || ""
        if data.empty?
          send.call(base(21, resp, 0x08, 0x01, 0x01)) # close
          break
        end
        chunks[pkt[20, 4].unpack1("N")] = data
      end
    end
    socket.close
    chunks.sort_by(&:first).map(&:last).join
  end

  # Broadcast the discovery beacon and collect gateways that answer (op 09 fe).
  # Returns { ip => reply_packet }. Handles the gateway getting a new DHCP IP.
  def discover(timeout = 2)
    socket = UDPSocket.new
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)
    socket.bind("0.0.0.0", PORT)
    beacon_pkt = beacon(rand(0x4000_0000..0x7FFF_FFFF), rand(0..0xFFFF_FFFF))
    (30_500..30_509).each { |p| socket.send(beacon_pkt, 0, "255.255.255.255", p) rescue nil }
    found = {}
    deadline = Time.now + timeout
    while Time.now < deadline && IO.select([socket], nil, nil, deadline - Time.now)
      pkt, addr = socket.recvfrom(4096)
      found[addr[3]] ||= pkt if pkt.getbyte(18) == 0x09 && pkt.getbyte(19) == 0xfe
    end
    socket.close
    found
  end
end

module LongTooth
  module_function

  # Find the Rgbw light's <device> block in a GetDevices reply, matched by its
  # RgbwBulbControl MiB — no hardcoded address, so it works on any gateway.
  def light_block(devx)
    devx.split("<device id=").find { |s| s.include?("RgbwBulbControl") }
  end

  # The light's device id (IPv6), discovered once per run from GetDevices.
  def light_id
    @light_id ||= begin
      blk = light_block(read("GetDevices")) or
        abort "no Rgbw light in GetDevices — is the gateway powered and paired?"
      blk[/\A"([^"]+)"/, 1]
    end
  end

  def bar(v, max = 255, w = 20)
    n = (v.to_f / max * w).round
    "[" + ("#" * n) + ("·" * (w - n)) + "]"
  end

  # Read a service, retrying a few times (individual reads can drop).
  def read(service, body = "empty", tries = 4)
    tries.times do
      r = call(service, body)
      return r unless r.empty?
      sleep 0.2
    end
    ""
  end

  # Decode an RgbwCurves blob into [[secs_of_day, percent], …].
  # Each 4-byte point = [lum:1][timestamp:3 BE secs]; percent = lum/255*100.
  def decode_curve(hex)
    hex.scan(/.{8}/).map do |pt|
      lum = pt[0, 2].to_i(16)
      t   = pt[2, 6].to_i(16)
      [t, (lum / 255.0 * 100).round]
    end
  end

  # Value (%) of a piecewise-linear curve at second-of-day t.
  def curve_at(points, t)
    return 0 if points.empty?
    return points.first[1] if t <= points.first[0]
    return points.last[1]  if t >= points.last[0]
    points.each_cons(2) do |(t0, v0), (t1, v1)|
      return (v0 + (v1 - v0) * (t - t0).to_f / (t1 - t0)).round if t.between?(t0, t1)
    end
    0
  end

  # Render a channel's Curve0+Curve1 as sparkline + key points.
  def render_curves(curves)
    bars = " ▁▂▃▄▅▆▇█"
    { "Red" => "31", "Green" => "32", "Blue" => "34", "White" => "37" }.each do |ch, col|
      pts = (decode_curve(curves["#{ch}Curve0"] || "") +
             decode_curve(curves["#{ch}Curve1"] || "")).sort_by(&:first)
      graph = (0..23).map { |h| bars[(curve_at(pts, h * 3600) / 100.0 * 8).round] }.join
      keys = pts.chunk { |x| x }.map(&:first)
                .map { |t, v| format("%02d:%02d=%d%%", t / 3600, t % 3600 / 60, v) }.join(" ")
      printf("    \e[%sm%-6s\e[0m %s  %s\n", col, ch, graph, keys)
    end
  end

  def programs
    xml = read("GetPrograms")
    abort "no data" if xml.empty?
    progs = xml.scan(%r{<program>(.*?)</program>}m)
    puts "  #{progs.size} stored program(s):"
    progs.each do |body,|
      name = body[%r{<name>([^<]*)</name>}, 1]
      id   = body[%r{<id>(\d+)</id>}, 1]
      curves = body.scan(%r{<var>([A-Za-z]+Curve[01])</var><val>([0-9a-f]*)</val>}).to_h
      puts "\n  \e[1m#{name}\e[0m (##{id})"
      render_curves(curves)
    end
  end

  # All gateway service handlers (from Ghidra RE of longtooth_test). Get* are
  # read-only; Set*/Add*/Delete*/Reset* write.
  SERVICES = %w[
    GetDevices GetDevicesByGroup GetDevicesByRoom GetRoomByDevice GetChannel
    GetCapabilities GetSystemPara GetGatewayVersion GetUpdateBuildVersion
    GetRecords GetIcons GetPrograms GetScenes GetGroups GetRooms GetUsers GetUser
    GetTimezone GetWifis GetRuleList GetRuleListDetail GetRuleDetail
    GetExternalSceneTriggers GetUpdateDeviceCache GetUpdateSingleDeviceCache
    GetUpdateFirmware
    SetMibVar SetBatchMibVar SetMibVarByGroup SetBatchMibVarByGroup SetChannel
    SetSystemPara SetIcon SetProgram SetScene SetOnOffScene SetOnOffSceneName
    SetGroup SetRoom SetUser SetTime SetTimezone SetWifi SetRule
    SetExternalSceneTrigger SetExternalSceneTriggers SetAllowNewDevices
    AddUser AllowAddDevice RefreshCache LoginUser lttest TestThroughput
    DeleteProgram DeleteScene DeleteOnOffScene DeleteGroup DeleteRoom DeleteUser
    DeleteRule DeleteExternalSceneTrigger RemoveDevice ResetGateway
  ].freeze

  def help
    puts <<~USAGE
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
    USAGE
    SERVICES.sort.each_slice(3) { |row| puts "  " + row.map { |s| s.ljust(28) }.join.rstrip }
  end

  # Fire a SetMibVar write (gateway executes on receipt; reply not needed).
  def set_mibvar(mib, var, val, device: light_id)
    body = "<command><device>#{device}</device><mib>#{mib}</mib>" \
           "<var>#{var}</var><val>#{val}</val></command>"
    return puts("  DRY  SetMibVar #{mib}.#{var} = #{val}") if ENV["DRY_RUN"]
    call("SetMibVar", body)
    puts "  set  #{mib}.#{var} = #{val}"
  end

  # mode demo [maxlevel] [time]  — start the on-device RGBW demo cycle
  # mode program                 — stop demo + hand every channel back to the schedule
  def mode(which = nil, *args)
    case which
    when "demo"
      maxlevel = (args[0] || 100).to_i.clamp(10, 100)   # peak brightness, percent
      time     = (args[1] || 60).to_i.clamp(1, 300)     # run time, seconds
      set_mibvar("RgbwDemoMode", "Time", time)
      set_mibvar("RgbwDemoMode", "MaxLevel", maxlevel)
      set_mibvar("RgbwDemoMode", "StartDemo", 1)
      puts "demo ON: #{maxlevel}% peak for #{time}s — 'mode program' to stop"
    when "program", "auto"
      set_mibvar("RgbwDemoMode", "StartDemo", 0)            # stop demo if running
      %w[Red Green Blue White].each { |ch| set_mibvar("RgbwWorkMode", "#{ch}Mode", 0) }
      puts "program mode restored — light resumes its loaded schedule"
    when "manual"
      chans = %w[Red Green Blue White]
      abort "usage: mode manual <r> <g> <b> <w>   (each 0-255)" unless args.size == 4
      vals = args.map { |a| a.to_i.clamp(0, 255) }
      chans.each_with_index { |ch, i| set_mibvar("RgbwBulbControl", "#{ch}LumTarget", vals[i]) }
      puts "manual R/G/B/W = #{vals.join('/')} — 'mode program' to restore the schedule"
    else
      abort "usage: mode demo [maxlevel%%=10-100] [secs=1-300] | manual <r> <g> <b> <w> | program"
    end
  end

  def status
    ver  = read("GetGatewayVersion").strip
    tz   = read("GetTimezone").strip
    devx = read("GetDevices")
    abort "no data — gateway silent (check power and the Gateway ID)" if devx.empty?

    dev = light_block(devx) or
      abort "GetDevices returned #{devx.bytesize} bytes but no Rgbw light in it"
    getv = ->(mib, var) { dev[/<mib id="#{mib}"[^>]*>.*?<var name="#{var}">([^<]*)/m, 1] }
    name = getv.call("_setting", "Name") || "Atlantik v4"
    temp = getv.call("RgbwTemperature", "Temperature")
    ct   = (getv.call("RgbwCurrentTime", "CurrentTime") || "0").to_i

    tempc = temp.to_f > 0 ? "#{temp.to_f.round(1)}°C" : "n/a"
    puts "  #{name}   [#{gateway}]  id #{gateway_id}  fw #{ver}"
    puts "  time #{format('%02d:%02d', ct / 3600, ct % 3600 / 60)} (#{tz})   temp #{tempc}"
    puts "  channels now:"
    { "Red" => "31", "Green" => "32", "Blue" => "34", "White" => "37" }.each do |ch, col|
      v = (getv.call("RgbwBulbControl", "#{ch}LumTarget") || "0").to_i
      mode = getv.call("RgbwWorkMode", "#{ch}Mode")
      printf("    \e[%sm%-6s\e[0m %s %3d%s\n", col, ch, bar(v), v, mode.to_i.zero? ? "" : "  MANUAL(#{mode})")
    end
    puts "  day schedule loaded (00→23h):"
    curves = {}
    %w[Red Green Blue White].each { |ch| [0, 1].each { |n| curves["#{ch}Curve#{n}"] = dev[/<var name="#{ch}Curve#{n}">([0-9a-f]*)/, 1] || "" } }
    render_curves(curves)
  end
end

case ARGV[0]
when "configure"
  LongTooth.configure
when nil, "help", "-h", "--help", "services"
  LongTooth.help
else
  LongTooth.configured!   # die early if .atlantik-gateway is missing/invalid
  case ARGV[0]
  when "status"   then LongTooth.status
  when "mode"     then LongTooth.mode(*ARGV[1..])
  when "programs" then LongTooth.programs
  else
    xml = LongTooth.call(ARGV[0], ARGV[1] || "empty")
    puts xml.empty? ? "no data returned" : xml
  end
end
