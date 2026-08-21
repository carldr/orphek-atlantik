#!/usr/bin/env ruby
# Parse the LongTooth pcap into a per-packet timeline so the tunnel handshake
# choreography is visible: seq, direction, length, connid, opcode+flags, and a
# snippet of any ASCII body. Handles classic pcap DLT_LINUX_SLL (tcpdump -i any).

path = ARGV[0] || "lt-capture.pcap"
data = File.binread(path)

magic = data[0, 4].unpack1("H*")
le = ["d4c3b2a1", "4d3cb2a1"].include?(magic)
u32 = ->(s) { le ? s.unpack1("V") : s.unpack1("N") }
linktype = u32.call(data[20, 4])                 # 113 = LINUX_SLL
off = 24
seq = 0
printf("%-4s %-3s %-5s %-9s %-6s %s\n", "seq", "dir", "len", "connid", "op fl", "body")
while off + 16 <= data.bytesize
  incl = u32.call(data[off + 8, 4])
  rec = data[off + 16, incl]
  off += 16 + incl
  seq += 1

  ip = linktype == 113 ? rec[16..] : rec[14..]
  next unless ip && (ip.getbyte(0) >> 4) == 4
  ihl = (ip.getbyte(0) & 0xf) * 4
  next unless ip.getbyte(9) == 17                # UDP
  src = ip[12, 4].bytes.join(".")
  udp = ip[ihl..]
  payload = udp[8..] || ""
  next if payload.empty?

  dir = src.end_with?(".114") ? "->" : (src.end_with?(".98") ? "<-" : "??")
  connid = payload[14, 4] ? payload[14, 4].unpack1("H*") : ""
  op = payload.getbyte(18) || 0
  fl = payload.getbyte(19) || 0
  body = payload[24..] || ""
  if ENV["FULL"]
    printf("%-4d %-3s %-5d %s\n", seq, dir, payload.bytesize, payload.unpack1("H*"))
  else
    ascii = body.gsub(/[^\x20-\x7e]/, ".")[0, 44]
    printf("%-4d %-3s %-5d %-9s %02x %02x  %s\n", seq, dir, payload.bytesize, connid, op, fl, ascii)
  end
end
