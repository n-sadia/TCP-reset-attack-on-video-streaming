# TCP Reset Attack on Video Streaming

**CSE 406 — Cyber Security Sessional**  
Bangladesh University of Engineering and Technology (BUET)

**Group Members**
- MD Shoaib Hossain (2105170)
- Nujhat Sadia (2105174)

---

## Overview

This project implements a TCP Reset (RST) injection attack that disrupts a live video stream, and a defense script that detects the attack. All attack and defense code is written from scratch using Python raw sockets — no packet crafting library is used.

---

## How the Attack Works

A TCP RST attack ends an active TCP connection by injecting a forged RST packet. A host accepts a RST if its sequence number falls inside the current receive window, and it never verifies who sent it. The attacker sits on the same network as the server and client, sniffs the live traffic to read the real sequence numbers, then forges a RST that the client accepts as genuine — killing the connection instantly.

---

## Lab Setup

### Requirements
- Host machine running Ubuntu (tested on 22.04)
- VirtualBox with a Host-Only network (`vboxnet0`, `192.168.56.0/24`)
- Three Ubuntu Server 22.04 VMs

### VM Configuration

| VM | IP | Role |
|---|---|---|
| server | 192.168.56.10 | Serves the video over HTTP |
| client | 192.168.56.11 | Streams the video (ffplay) |
| attacker | 192.168.56.12 | Sniffs traffic and injects RST |

All three VMs share the same Host-Only network. The attacker's interface runs in promiscuous mode so it can see server↔client traffic.

### Network Setup (each VM)

```bash
# set static IP (adjust address per VM)
echo -e "network:\n  version: 2\n  ethernets:\n    enp0s8:\n      dhcp4: no\n      addresses: [192.168.56.10/24]" \
  | sudo tee /etc/netplan/99-lab.yaml
sudo chmod 600 /etc/netplan/99-lab.yaml
sudo netplan apply
```

### Required packages (all VMs)

```bash
sudo apt install -y python3 python3-pip tcpdump net-tools iproute2
```

### Client only — ffplay for video playback

```bash
sudo apt install -y ffmpeg
```

---

## Files

```
sniffer.py    — sniffs the server→client flow, extracts seq/ports
rst.py        — forges and sends the RST packet
detector.py   — runs on client, detects suspicious RSTs mid-stream
server.py     — rate-limited HTTP server (keeps buffer small for demo)
```

---

## Running the Attack

### Step 1 — prepare the server

Put a video file (`sample.mp4`) in the home directory, then start the rate-limited server:

```bash
# on server
python3 ~/server.py
```

### Step 2 — prepare the client

Disable RFC 5961 challenge-ACK rate limiting (required for the attack to land):

```bash
# on client
sudo sysctl -w net.ipv4.tcp_challenge_ack_limit=1000000
```

Start the video:

```bash
# on client
ffplay -fflags nobuffer http://192.168.56.10:8000/sample.mp4
```

### Step 3 — run the attack

Once the video is playing, run the attacker:

```bash
# on attacker
sudo python3 ~/rst.py
```

The attacker sniffs the live flow, reads the current sequence number from each data packet, computes `next_seq = seq + payload_length`, and fires a forged RST to the client spoofing the server's IP and port. The loop retries on every new data packet until one RST lands inside the client's receive window.

### Expected result

**Client:** ffplay freezes and prints:
```
Stream ends prematurely
Packet corrupt
Connection reset by peer
```

**Server:** prints:
```
ConnectionResetError: [Errno 104] Connection reset by peer
```

**Attacker:** prints:
```
[*] Packet #1: next_seq=XXXXXXXXX  port=XXXXX
[+] RST sent via AF_PACKET!
    spoofed src: 192.168.56.10:8000
    target:      192.168.56.11:XXXXX
    seq:         XXXXXXXXX
...
```

---

## Capturing Evidence

On attacker, run tcpdump alongside the attack:

```bash
# Terminal 1 — capture
sudo tcpdump -i enp0s8 -n -w ~/attack.pcap "tcp and host 192.168.56.10"

# Terminal 2 — attack
sudo python3 ~/rst.py
```

Transfer to host:

```bash
scp base@192.168.56.12:~/attack.pcap ~/Desktop/
```

Open in Wireshark, filter `tcp.flags.reset == 1`. The forged RST shows:
- `Src: 192.168.56.10` — spoofed as server
- `Dst: 192.168.56.11` — client
- `Src Port: 8000` — spoofed as server port
- `Flags: 0x004 (RST)`
- `Window: 0`, `Len: 0`

The direction flip (`client → server [RST]`) in the capture marks the moment the client accepted the forged RST and sent its own cleanup RST to the server.

---

## Running the Defense

The detector runs on the **client** and watches for RST packets arriving while a connection is still actively streaming data. A legitimate server RST only appears after the stream ends — a RST mid-stream is a sign of injection.

```bash
# on client — start detector before playing the video
sudo python3 ~/detector.py
```

When the attack fires, the detector prints:

```
[!] ==================================================
[!] ALERT: Suspicious RST detected!
[!] From:            192.168.56.10:8000
[!] To:              192.168.56.11:42132
[!] RST seq:         4244054589
[!] Data was flowing 0.003s ago
[!] This connection was active — RST may be forged!
[!] Time:            06:41:23
[!] ==================================================
```

### Detection logic

The detector tracks the timestamp of the last data packet for every active connection. When a RST arrives from the server direction, it checks how long ago data was flowing:
- **Under 2 seconds** → suspicious, raises alert.
- **Over 2 seconds** → RST after idle period, probably legitimate.

### Limitation

This is **detection, not prevention**. The alert fires after the RST has already been accepted and the connection is dead. True prevention requires either RFC 5961 (challenge-ACK, disabled here to demonstrate the attack) or a transport that doesn't use TCP RST (QUIC/UDP-based streaming is immune to this attack entirely).

---

## Key Technical Points

### Why `next_seq = seq + payload_length`

TCP numbers every byte in the stream. The sequence number in a segment marks the first byte of that segment's payload. After receiving a segment, the receiver expects the *next* byte — so `next_seq = seq + payload_length` is the exact value sitting at the edge of the receive window. A RST carrying this value is guaranteed to be in-window and accepted.

### Why AF_PACKET instead of SOCK_RAW/IPPROTO_RAW

Ubuntu 22.04 blocks spoofed source IPs sent via `SOCK_RAW`/`IP_HDRINCL` even as root (reverse path filtering). `AF_PACKET` sends a raw Ethernet frame directly to the network driver, bypassing IP routing, source-address validation, and the iptables OUTPUT chain entirely.

### Why the attack fires multiple RSTs

The sniffer and injector run sequentially with no feedback. Between sniffing a packet and sending the RST, the server sends more data and the receive window advances. The loop compensates by retrying with fresh sequence numbers on every new data packet. One RST eventually lands at exactly the right window position and is accepted.

### Why the server gets ConnectionResetError

The forged RST goes to the client only. The server is never told to close. When the client accepts the RST and tears down its socket, the server keeps sending the next data chunk — but receives a RST back from the client's OS (which has no matching socket anymore). That RST triggers `ConnectionResetError` on the server side.

---

## Assumptions

- The attacker is on the same Layer-2 segment and can sniff server↔client traffic in promiscuous mode.
- The client does not enforce RFC 5961 strict RST acceptance (disabled with `tcp_challenge_ack_limit`).
- No IPsec or transport-layer authentication is in use.
- No host firewall blocks spoofed packets arriving from within the same subnet.

These are all true of the default VirtualBox Host-Only lab environment.

---

## References

- RFC 793 — Transmission Control Protocol, IETF
- RFC 5961 — Improving TCP's Robustness to Blind In-Window Attacks, IETF
