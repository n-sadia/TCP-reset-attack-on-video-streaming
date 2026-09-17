# TCP Reset Attack on Video Streaming

**CSE 406 — Computer Security Sessional**  
Bangladesh University of Engineering and Technology (BUET)

**Group Members**
- Nujhat Sadia (2105174)
- MD Shoaib Hossain (2105170)

---

## Overview

This project implements a TCP Reset (RST) injection attack that disrupts a live video stream, and two countermeasures: a detection script and a prevention script. All code is written from scratch using Python raw sockets — no packet crafting library is used.

---

## How the Attack Works

A TCP RST attack ends an active TCP connection by injecting a forged RST packet. A host accepts a RST if its sequence number falls inside the current receive window, and it never verifies who sent it. The attacker sits on the same network, sniffs live traffic to read real sequence numbers, then forges a RST the client accepts as genuine — killing the connection instantly.

---

## Lab Setup

### Requirements
- Host machine running Ubuntu (tested on 22.04)
- VirtualBox with a Host-Only network (`vboxnet0`, `192.168.56.0/24`)
- Three Ubuntu Server 22.04 VMs

### VM Configuration

| VM | IP | Role |
|---|---|---|
| server | 192.168.56.10 | Serves the video over HTTP port 8000 |
| client | 192.168.56.11 | Streams the video (ffplay) |
| attacker | 192.168.56.12 | Sniffs traffic and injects forged RST |

### Network Setup (each VM)

```bash
echo -e "network:\n  version: 2\n  ethernets:\n    enp0s8:\n      dhcp4: no\n      addresses: [192.168.56.10/24]" \
  | sudo tee /etc/netplan/99-lab.yaml
sudo chmod 600 /etc/netplan/99-lab.yaml
sudo netplan apply
```

### Required packages

```bash
sudo apt install -y python3 python3-pip tcpdump net-tools iproute2 ffmpeg
# client only (for prevention.py):
sudo apt install -y libnetfilter-queue-dev libnetfilter-queue1 python3-dev build-essential
sudo pip3 install NetfilterQueue --break-system-packages
```

---

## Files

```
sniffer.py      — raw AF_PACKET socket sniffer; extracts seq/ports from live flow
rst.py          — forges and sends the RST using AF_PACKET (Ethernet level)
server.py       — rate-limited HTTP video server (50 KB/s keeps client buffer small)
detector.py     — detection countermeasure; alerts on RST arriving mid-stream
prevention.py   — prevention countermeasure; drops forged RSTs before kernel sees them
```

---

## Running the Attack

**Server:**
```bash
python3 ~/server.py
```

**Client** — disable RFC 5961 rate limiting first, then play:
```bash
sudo sysctl -w net.ipv4.tcp_challenge_ack_limit=1000000
ffplay -fflags nobuffer -flags low_delay http://192.168.56.10:8000/sample.mp4
```

**Attacker** — once video is playing:
```bash
sudo python3 ~/rst.py
```

### Expected result

**Client:**
```
Stream ends prematurely at XXXXXXX, should be 6187860
Packet corrupt / partial file / Invalid NAL unit size
```
Video freezes mid-playback.

**Server:**
```
ConnectionResetError: [Errno 104] Connection reset by peer
```

**Attacker:**
```
[*] Packet #1: next_seq=XXXXXXXXX  port=XXXXX
[+] RST sent via AF_PACKET!
    spoofed src: 192.168.56.10:8000
    target:      192.168.56.11:XXXXX
    seq:         XXXXXXXXX
```

---

## Why AF_PACKET Instead of IPPROTO_RAW

Ubuntu 22.04 blocks spoofed source IPs sent via the IP layer (`SOCK_RAW`/`IP_HDRINCL`) even as root, due to reverse-path filtering. Sending as a raw Ethernet frame (`AF_PACKET`) bypasses this entirely — the packet goes straight to the network driver without IP routing or source-address checks.

---

## Capturing Evidence

```bash
# attacker terminal 1 — capture
sudo tcpdump -i enp0s8 -n -w ~/attack.pcap "tcp and host 192.168.56.10"

# attacker terminal 2 — attack
sudo python3 ~/rst.py

# transfer to host
scp base@192.168.56.12:~/attack.pcap ~/Desktop/
```

Open in Wireshark, filter `tcp.flags.reset == 1`. The direction flip (`client → server [RST]`) marks the moment a forged RST was accepted.

---

## Countermeasures

### Detection — `detector.py`

Runs on the **client**. Sniffs its own interface and tracks the timestamp of the last data packet per connection. When a RST arrives from the server while data was flowing less than 2 seconds ago, it raises an alert.

```bash
sudo python3 ~/detector.py
```

**Alert output:**
```
[!] ALERT: Suspicious RST detected!
[!] From:            192.168.56.10:8000
[!] To:              192.168.56.11:42132
[!] RST seq:         4244054589
[!] Data was flowing 0.002s ago
[!] This connection was active — RST may be forged!
```

**Limitation:** detection only. The alert fires after the RST has already been accepted and the connection is dead. Useful for logging and alerting, but does not keep the stream alive.

---

### Prevention — `prevention.py`

Runs on the **client**. Intercepts the forged RST **before** the kernel's TCP stack processes it using `NetfilterQueue`. Applies the same behavioral logic as the detector — if data was flowing recently, the RST is forged, so drop it; otherwise pass it through.

```bash
sudo python3 ~/prevention.py
```

**How it works:**

1. On startup, adds an iptables rule that sends incoming RSTs from the server to `NFQUEUE --queue-num 1`:
   ```
   iptables -I INPUT -p tcp --tcp-flags RST RST -s 192.168.56.10 --sport 8000 -j NFQUEUE --queue-num 1
   ```
2. A background thread sniffs data packets and records the last data timestamp per connection (same logic as `detector.py`).
3. The NetfilterQueue callback receives each RST before the kernel sees it:
   - Data flowing **less than 2 seconds ago** → `packet.drop()` — RST silently discarded, TCP connection stays alive.
   - Otherwise → `packet.accept()` — RST passed to kernel normally.
4. On exit (Ctrl+C), the iptables rule is removed automatically.

**Prevention output:**
```
[BLOCKED] Forged RST from 192.168.56.10:8000 seq=4244054589 data was flowing 0.003s ago — DROPPED
```

**Why the iptables rule is not an environment change:**
The rule is added by the script at startup and removed when it exits. It exists only while `prevention.py` is running — starting and stopping the script is the on/off switch. The environment is otherwise unchanged.

**Limitation:** prevention works by dropping the RST before the kernel sees it. A determined attacker using ARP spoofing or a more advanced on-path technique could potentially bypass the nfqueue callback. True network-level prevention without any code would require RFC 5961, TLS, or QUIC.

---

## Demo: Showing Detection and Prevention

**Round 1 — attack without countermeasures (shows attack works):**
```bash
# client
ffplay -fflags nobuffer http://192.168.56.10:8000/sample.mp4
# attacker → rst.py fires → video freezes
```

**Round 2 — attack with detection (shows alert fires):**
```bash
# client terminal 1
sudo python3 ~/detector.py
# client terminal 2
ffplay -fflags nobuffer http://192.168.56.10:8000/sample.mp4
# attacker → rst.py fires → video freezes + ALERT printed by detector
```

**Round 3 — attack with prevention (shows RST blocked, video survives):**
```bash
# client terminal 1
sudo python3 ~/prevention.py
# client terminal 2
ffplay -fflags nobuffer http://192.168.56.10:8000/sample.mp4
# attacker → rst.py fires → BLOCKED printed, video keeps playing
```

---

## Countermeasure Comparison

| Countermeasure | Approach | Effect | Implemented |
|---|---|---|---|
| `detector.py` | Behavioral anomaly (RST mid-stream) | Detects & alerts | Yes |
| `prevention.py` | NetfilterQueue RST interception | Drops forged RSTs | Yes |
| RFC 5961 | `sysctl` kernel parameter | Prevents most RSTs | No |
| TLS | Transport encryption | Data integrity | No |
| QUIC/UDP | Different transport | RST immune | No |

---

## Key Technical Points

### Why `next_seq = seq + payload_length`
TCP numbers every byte in the stream. After receiving a segment, the receiver expects the next byte at `seq + payload_length`. A RST carrying this value sits at the exact edge of the receive window and is guaranteed to be accepted.

### Why the loop fires multiple RSTs
Between sniffing a packet and sending the RST, the server sends more data and the window advances. The loop retries with a fresh `next_seq` on every new packet. In testing, connections died after 5–15 RSTs.

### Why the server gets ConnectionResetError
The forged RST goes only to the client. The server keeps sending until it gets a real RST back from the client's OS (which has no socket for the dead connection), triggering `ConnectionResetError`.

### Checksum computation
Both checksums are computed manually:
- **IP checksum:** one's complement sum over the 20-byte IP header.
- **TCP checksum:** one's complement sum over a 12-byte pseudo-header (src IP, dst IP, zero byte, protocol=6, TCP length) + 20-byte TCP header.

---

## Assumptions

- Attacker is on the same L2 segment and can sniff in promiscuous mode.
- `tcp_challenge_ack_limit` is raised on the client (default 100 requires very fast RST firing; raising to 1000000 removes this constraint in lab).
- No IPsec or transport-level authentication on the stream.
- No host firewall blocks spoofed packets from the same subnet.

---

## References

- RFC 793, Transmission Control Protocol, IETF, 1981.
- RFC 5961, Improving TCP's Robustness to Blind In-Window Attacks, IETF, 2010.
