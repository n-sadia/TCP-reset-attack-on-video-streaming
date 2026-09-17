#!/usr/bin/env python3
"""
detector.py — TCP RST Injection Detector
Run on the CLIENT to detect forged RST attacks.
sudo python3 ~/detector.py
"""

import socket
import struct
import time

IFACE       = "enp0s8"
SERVER_IP   = "192.168.56.10"
SERVER_PORT = 8000

ETH_HDR_LEN = 14

# Tracks active connections that have seen recent data
# key   = (src_ip, src_port, dst_ip, dst_port)
# value = time of last data packet
active_connections = {}

# --- same parsing functions you already have in sniffer.py ---

def parse_ethernet(frame):
    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", frame[:14])
    return ethertype

def parse_ip(packet):
    fields = struct.unpack("!BBHHHBBH4s4s", packet[:20])
    version_ihl  = fields[0]
    total_length = fields[2]
    protocol     = fields[6]
    src_ip       = socket.inet_ntoa(fields[8])
    dst_ip       = socket.inet_ntoa(fields[9])
    ihl_bytes    = (version_ihl & 0x0F) * 4
    return ihl_bytes, protocol, src_ip, dst_ip, total_length

def parse_tcp(segment):
    fields      = struct.unpack("!HHIIBBHHH", segment[:20])
    src_port    = fields[0]
    dst_port    = fields[1]
    seq         = fields[2]
    data_offset = fields[4]
    flags       = fields[5]
    tcp_hdr_len = (data_offset >> 4) * 4
    return src_port, dst_port, seq, tcp_hdr_len, flags

# TCP flag constants
FLAG_RST = 0x04
FLAG_FIN = 0x01
FLAG_SYN = 0x02

def detect():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.ntohs(0x0003))
    sock.bind((IFACE, 0))

    print(f"[*] Detector running on {IFACE}")
    print(f"[*] Watching for suspicious RSTs from {SERVER_IP}:{SERVER_PORT}")
    print(f"[*] Press Ctrl+C to stop\n")

    while True:
        frame, _ = sock.recvfrom(65535)

        ethertype = parse_ethernet(frame)
        if ethertype != 0x0800:
            continue

        ip_packet = frame[ETH_HDR_LEN:]
        ihl, proto, src_ip, dst_ip, total_len = parse_ip(ip_packet)

        if proto != 6:   # not TCP
            continue

        tcp_segment  = ip_packet[ihl:]
        src_port, dst_port, seq, tcp_hdr_len, flags = parse_tcp(tcp_segment)
        payload_len  = total_len - ihl - tcp_hdr_len
        conn_key     = (src_ip, src_port, dst_ip, dst_port)

        # Step 1 — track data packets from server to client
        # If we see payload > 0, the connection is actively streaming
        if (src_ip == SERVER_IP and
            src_port == SERVER_PORT and
            payload_len > 0):
            active_connections[conn_key] = time.time()

        # Step 2 — detect RST from server direction
        if (flags & FLAG_RST) and src_ip == SERVER_IP and src_port == SERVER_PORT:

            last_data_time = active_connections.get(conn_key)

            if last_data_time is not None:
                seconds_since_data = time.time() - last_data_time

                if seconds_since_data < 2.0:
                    # RST arrived while data was still flowing recently
                    # A legitimate server RST would only come after FIN or
                    # a long idle period — this is suspicious
                    print(f"[!] {'='*50}")
                    print(f"[!] ALERT: Suspicious RST detected!")
                    print(f"[!] From:            {src_ip}:{src_port}")
                    print(f"[!] To:              {dst_ip}:{dst_port}")
                    print(f"[!] RST seq:         {seq}")
                    print(f"[!] Data was flowing {seconds_since_data:.3f}s ago")
                    print(f"[!] This connection was active — RST may be forged!")
                    print(f"[!] Time:            {time.strftime('%H:%M:%S')}")
                    print(f"[!] {'='*50}\n")
                else:
                    # RST came long after data stopped — probably legitimate
                    print(f"[*] RST from server (looks normal, "
                          f"{seconds_since_data:.1f}s after last data)")
            else:
                # RST with no prior data seen — odd but not actionable
                print(f"[*] RST from server on unknown connection "
                      f"{src_ip}:{src_port} → {dst_ip}:{dst_port}")

if __name__ == "__main__":
    detect()