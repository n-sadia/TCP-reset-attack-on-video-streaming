#!/usr/bin/env python3
"""
prevention.py — RST Prevention using NetfilterQueue
Intercepts RST packets BEFORE the kernel processes them.
sudo python3 ~/prevention.py
"""

from netfilterqueue import NetfilterQueue
import socket
import struct
import time

last_data_time = {}
FLAG_RST = 0x04

def parse_ip_tcp(data):
    ihl       = (data[0] & 0x0F) * 4
    proto     = data[9]
    src_ip    = socket.inet_ntoa(data[12:16])
    dst_ip    = socket.inet_ntoa(data[16:20])
    total_len = struct.unpack("!H", data[2:4])[0]

    if proto != 6:
        return None

    tcp         = data[ihl:]
    src_port, dst_port = struct.unpack("!HH", tcp[0:4])
    seq         = struct.unpack("!I", tcp[4:8])[0]
    data_offset = (tcp[12] >> 4) * 4
    flags       = tcp[13]
    payload_len = total_len - ihl - data_offset

    return src_ip, src_port, dst_ip, dst_port, seq, flags, payload_len

def callback(packet):
    data   = packet.get_payload()
    result = parse_ip_tcp(data)

    if result is None:
        packet.accept()
        return

    src_ip, src_port, dst_ip, dst_port, seq, flags, plen = result
    conn_key = (src_ip, src_port, dst_ip, dst_port)

    # track data packets — note their arrival time
    if plen > 0 and not (flags & FLAG_RST):
        last_data_time[conn_key] = time.time()
        packet.accept()
        return

    # inspect RST packets
    if flags & FLAG_RST:
        last_seen = last_data_time.get(conn_key)
        if last_seen and (time.time() - last_seen) < 2.0:
            print(f"[BLOCKED] Forged RST from {src_ip}:{src_port} "
                  f"seq={seq} — dropped!")
            packet.drop()   # RST never reaches the kernel
            return
        else:
            print(f"[ALLOWED] RST from {src_ip}:{src_port} "
                  f"(looks legitimate)")

    packet.accept()

# add iptables rule programmatically
import os
os.system("iptables -I INPUT -p tcp --tcp-flags RST RST "
          "-s 192.168.56.10 --sport 8000 -j NFQUEUE --queue-num 1")

print("[*] Prevention active — intercepting RSTs before kernel sees them")
print("[*] Press Ctrl+C to stop\n")

nfq = NetfilterQueue()
nfq.bind(1, callback)

try:
    nfq.run()
except KeyboardInterrupt:
    print("\n[*] Stopped.")
finally:
    # clean up iptables rule on exit
    os.system("iptables -D INPUT -p tcp --tcp-flags RST RST "
              "-s 192.168.56.10 --sport 8000 -j NFQUEUE --queue-num 1")
    nfq.unbind()
    print("[*] iptables rule removed.")