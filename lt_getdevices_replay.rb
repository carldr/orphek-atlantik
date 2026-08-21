#!/usr/bin/env ruby
# Replay the captured LongTooth "GetDevices" call to the gateway and print any
# reply. Read-only probe — first attempt to speak LongTooth without the app.
# Frame decoded in FINDINGS.md §19. Bytes are the verbatim 74-byte UDP payload
# the phone (192.168.2.114) sent in lt-capture.pcap.

require 'socket'

GATEWAY = '192.168.2.98'
PORT    = 30500

payload = [
  '48000000',                                                             # [len:4] LE = 0x48 (74-2)
  '00000000000000000000',                                                 # [addr:10] (zero)
  'b70efd07',                                                             # [connid:4]
  '0401',                                                                 # opcode 0x04 (open+request) + flag
  '017803000001000000460051920100000001000000bdd40f2249f102f80000000000', # ~34B request sub-header (TBD)
  '0a47657444657669636573',                                              # svc: u8 len=10 + "GetDevices"
  '05000000656d707479'                                                    # body: u32 len=5 + "empty"
].join

pkt = [payload].pack('H*')
puts "sending #{pkt.bytesize} bytes to #{GATEWAY}:#{PORT}"

sock = UDPSocket.new
sock.bind('0.0.0.0', PORT)          # gateway replies to our source port (30500)
sock.send(pkt, 0, GATEWAY, PORT)

# Collect every reply packet for 3s (gateway may send ack + data separately).
outfile = File.join(__dir__, 'lt-getdevices-reply.bin')
File.open(outfile, 'wb') do |f|
  n = 0
  loop do
    break unless IO.select([sock], nil, nil, 3)
    data, from = sock.recvfrom(8192)
    n += 1
    f.write(data)
    puts "reply ##{n} from #{from[3]}:#{from[1]} — #{data.bytesize} bytes"
    data.unpack1('H*').scan(/../).each_slice(16) do |row|
      ascii = [row.join].pack('H*').gsub(/[^\x20-\x7e]/, '.')
      puts format('  %-48s  %s', row.join(' '), ascii)
    end
  end
  puts n.zero? ? 'no reply within 3s' : "saved raw replies -> #{outfile}"
end
sock.close
