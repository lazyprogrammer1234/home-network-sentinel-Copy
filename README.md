# Home Network Sentinel

A lightweight, reliable Python security tool for local network device discovery, whitelist auditing, and intrusion alerting using Address Resolution Protocol (ARP).

Designed as a clean, modular computer science project focusing on fundamental Layer 2 networking concepts, automated testing, and secure credential handling with minimal dependencies.

---

## Architecture & Concept

### How ARP Discovery Works
On an IPv4 local network, devices communicate over Ethernet using Hardware (MAC) addresses. Before sending IP packets to a local host, a computer broadcasts an **ARP request** asking: *"Who has IP `x.x.x.x`? Tell `my_ip`"*. The destination host replies directly with its MAC address.

**Home Network Sentinel** broadcasts ARP requests across a designated IPv4 subnet using [Scapy](https://scapy.net/). Active devices respond with their hardware MAC address. The tool normalizes each address, compares it against a user-defined whitelist (`whitelist.json`), and classifies devices as **KNOWN** or **UNKNOWN**.

```
       +---------------------------------------------+
       |           sentinel.scanner (ARP)            |
       |  Crafts Ethernet broadcast & ARP requests   |
       +---------------------------------------------+
                              |
                     Discovered [IP, MAC]
                              v
       +---------------------------------------------+
       |         sentinel.classifier & Whitelist     |
       |  Normalizes MACs & checks whitelist.json    |
       +---------------------------------------------+
                              |
                  Classified Device Records
                              v
               +-----------------------------+
               | Mode: Single Scan / Monitor |
               +-----------------------------+
                /                           \
               v                             v
     [ Single-Scan Mode ]           [ Monitor Mode ]
      Renders terminal table         Periodic scan loop
      Sorted by IP address           In-memory deduplication
                                     Terminal alert + Discord
```

---

## Features

- **Layer 2 ARP Discovery**: Discovers active IPv4 hosts on your local subnet without intrusive port scanning.
- **Device Whitelist & Classification**: Match hardware addresses against a friendly-name JSON whitelist to instantly spot unrecognized devices.
- **Deduplicated Periodic Monitoring**: Re-scans the subnet at a configurable interval and suppresses repeat alerts for already-flagged devices during the active session.
- **Alert Channels**: Clear ANSI terminal notifications with optional real-time Discord webhook delivery.
- **Safe by Design**: Webhook credentials are read exclusively from environment variables and strictly sanitized to prevent credential leaks in logs.
- **100% Mocked Offline Test Suite**: All unit tests run unprivileged without requiring `sudo`, network sockets, or external API endpoints.

---

## Project Structure

```
HOME NETWROK SCANNER/
├── sentinel/                   # Core application package
│   ├── __init__.py
│   ├── __main__.py             # CLI entry point and argument parsing
│   ├── scanner.py              # ARP discovery via Scapy & subnet validation
│   ├── whitelist.py            # Whitelist parsing, lookup, and MAC normalization
│   ├── classifier.py           # Device labeling (KNOWN / UNKNOWN)
│   ├── display.py              # Pure-Python formatted terminal table renderer
│   ├── monitor.py              # Periodic loop, error recovery, and deduplication
│   └── notify.py               # Terminal alerts and Discord webhook integration
├── tests/                      # Automated unit test suite (63 tests)
│   ├── __init__.py
│   ├── test_cli.py             # CLI argument validation and dispatch tests
│   ├── test_scanner.py         # Subnet parsing and MAC normalization tests
│   ├── test_whitelist.py       # JSON loading, format validation, and lookup tests
│   ├── test_classifier.py      # Device classification logic tests
│   ├── test_monitor.py         # Loop behavior, error recovery, and deduplication tests
│   └── test_notify.py          # Terminal output, mocked Discord, and secret sanitization
├── requirements.txt            # Pinned runtime and testing dependencies
├── whitelist.example.json      # Safe template with fictional MAC addresses
├── .env.example                # Safe environment variable configuration template
├── .gitignore                  # Excludes private MACs, .env, venv, and caches
└── README.md                   # Project documentation
```

---

## Operating System & Permissions

### Why Raw Sockets Require Elevated Privileges
Crafting Layer 2 Ethernet frames (`Ether() / ARP()`) requires raw socket access:
- **macOS**: Access to `/dev/bpf*` (Berkeley Packet Filter) devices requires root (`sudo`).
- **Linux**: Opening raw sockets (`AF_PACKET`) requires `CAP_NET_RAW` privileges (or `sudo`).

### Privilege Scope
Elevated privileges are **strictly restricted to the packet send/receive operation** in `sentinel.scanner.scan()`. Subnet validation, whitelist management, classification, reporting, and all automated unit tests run completely unprivileged.

---

## Installation & Setup

### 1. Prerequisites
- Python 3.10+ (tested and verified on Python 3.14)
- macOS or Linux

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Your Whitelist
Copy the safe example file to create your local whitelist:
```bash
cp whitelist.example.json whitelist.json
```
Edit `whitelist.json` with your authorized devices. You can find device MAC addresses on your network using `arp -a` or by checking your router's administration interface.

```json
{
  "devices": [
    {"mac": "aa:bb:cc:11:22:33", "name": "Main Router"},
    {"mac": "11:22:33:44:55:66", "name": "Work Laptop"}
  ]
}
```
*(Note: `whitelist.json` is ignored by `.gitignore` to prevent committing your real hardware addresses to version control.)*

---

## Usage Guide

Find your active network interface and subnet:
- **macOS**: Run `ifconfig` (look for `en0` or `en1` with an `inet` IP, e.g., `192.168.1.5 netmask 0xffffff00` &rarr; subnet `192.168.1.0/24`).
- **Linux**: Run `ip addr` or `ip route` (e.g., `eth0` or `wlan0`).

### 1. Single Scan (Default Mode)
Scan the subnet once and display a formatted device table:
```bash
sudo venv/bin/python -m sentinel --subnet 192.168.1.0/24 --iface en0
```

Sample output:
```
+---------------+-------------------+--------------------+--------+
| IP Address    | MAC Address       | Name               | Status |
+---------------+-------------------+--------------------+--------+
| 192.168.1.1   | aa:bb:cc:11:22:33 | Main Router        | KNOWN  |
| 192.168.1.20  | de:ad:be:ef:00:01 |                    | UNKNOWN|
| 192.168.1.35  | 11:22:33:44:55:66 | Work Laptop        | KNOWN  |
+---------------+-------------------+--------------------+--------+

Devices found: 3  |  Known: 2  |  Unknown: 1
```

### 2. Continuous Monitoring Mode
Run repeated scans to detect when unknown devices join the network:
```bash
sudo venv/bin/python -m sentinel --subnet 192.168.1.0/24 --iface en0 --monitor --interval 30
```
- Alerts are printed to the terminal immediately upon first sighting of an unknown MAC.
- Within an active session, duplicate alerts for the same MAC are suppressed.
- Stop monitoring cleanly at any time by pressing `Ctrl-C`.

### 3. Optional Discord Webhook Alerts
To receive push notifications on Discord when an unknown device appears:
1. Create a webhook in your Discord channel (`Edit Channel` &rarr; `Integrations` &rarr; `Webhooks`).
2. Set the environment variable:
   ```bash
   export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
   ```
3. Run the monitor command:
   ```bash
   sudo --preserve-env=DISCORD_WEBHOOK_URL venv/bin/python -m sentinel --subnet 192.168.1.0/24 --monitor
   ```
   *(Note: The `--preserve-env` flag passes the webhook environment variable into the elevated session).*

---

## CLI Options

| Argument | Description | Default |
|---|---|---|
| `--subnet` | *(Required)* Target IPv4 subnet in CIDR format (e.g., `192.168.1.0/24`) | None |
| `--iface` | Network interface to bind (e.g., `en0`, `eth0`) | Scapy default |
| `--whitelist` | Path to whitelist JSON file | `whitelist.json` |
| `--timeout` | Seconds to wait for ARP replies per scan | `2.0` |
| `--monitor` | Enable continuous monitoring loop | `False` |
| `--interval` | Seconds between scans in monitor mode | `60` |

---

## Running the Automated Test Suite

All unit tests are fully isolated and mock both network and HTTP calls. You do **not** need `sudo` or an internet connection to run tests:

```bash
venv/bin/python -m pytest tests/ -v
```

Expected output:
```
============================== 63 passed in 0.16s ==============================
```

---

## Troubleshooting

- **`PermissionError: Sending ARP packets requires root privileges`**:
  Make sure you execute the scan with `sudo`. Unprivileged processes cannot send raw Layer 2 packets.
- **`No devices found`**:
  Verify your interface name (`--iface en0`) and confirm that the subnet matches your current IP address and netmask.
- **Discord notifications not arriving**:
  Check that `DISCORD_WEBHOOK_URL` is exported in your environment. If running with `sudo`, remember to include `--preserve-env=DISCORD_WEBHOOK_URL`. If the webhook request fails, Sentinel logs a warning and continues scanning without crashing.

---

## Limitations & Defensive Guidance

1. **Broadcast Domain Boundary**: ARP requests operate at Layer 2 and cannot traverse routers or route across multiple VLANs. The scanner only discovers devices on your immediate local broadcast domain.
2. **Sleeping / Low-Power Devices**: Devices in deep sleep, airplane mode, or power-saving states do not respond to ARP requests and will not be listed until they become active.
3. **Private / Randomized MAC Addresses**: Modern mobile operating systems (iOS, Android, Windows 11) frequently randomize Wi-Fi MAC addresses by default for privacy. A known family device might appear as `UNKNOWN` if "Private Wi-Fi Address" is enabled.
4. **Investigative Prompt vs. Proof of Attack**: An `UNKNOWN` MAC indicates an unrecognized device on the network segment. It is an alert to investigate, not definitive evidence of malicious activity.
5. **Authorized Use Only**: Only execute this tool on networks you own or have explicit written permission to monitor.
