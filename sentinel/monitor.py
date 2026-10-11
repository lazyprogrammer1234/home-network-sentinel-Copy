"""
monitor.py – Periodic scanning loop with alert deduplication.

Key concepts:

1. Deduplication (in-memory set):
   We keep a `set` of MAC addresses we have already alerted on.  The first
   time an unknown MAC appears, we alert and add it to the set.  Subsequent
   scans that see the same MAC are silently ignored.  The set resets when
   the process restarts – this is intentional and sufficient for a
   session-level deduplication requirement.

2. Scan failure recovery:
   If a single scan raises an exception (e.g. a transient network hiccup),
   we log the error and continue to the next interval.  The loop does not
   crash.

3. Separation of concerns:
   monitor.py orchestrates: scan → classify → deduplicate → alert.
   It delegates each step to its own module and stays easy to read.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime

from sentinel import classifier
from sentinel import notify
from sentinel.classifier import STATUS_UNKNOWN
from sentinel.whitelist import normalize_mac


def _log(message: str) -> None:
    """Print a timestamped info message to stdout."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {message}")


def run_monitor(
    subnet: str,
    whitelist: dict[str, str],
    interval: int = 60,
    iface: str | None = None,
    timeout: float = 2.0,
) -> None:
    """Start the monitoring loop.  Runs until interrupted with Ctrl-C.

    Parameters
    ----------
    subnet:
        IPv4 subnet in CIDR notation, e.g. "192.168.29.0/24".
    whitelist:
        Pre-loaded whitelist dict {normalised_mac: name}.
    interval:
        Seconds between scans.  Default 60.
    iface:
        Network interface name, e.g. "en0".  None lets Scapy choose.
    timeout:
        ARP reply wait time in seconds.  Default 2.0.
    """
    # alerted_macs: MACs we have already sent an alert for this session.
    # Using a set gives O(1) lookup and automatically deduplicates.
    alerted_macs: set[str] = set()

    _log(f"Monitoring {subnet} every {interval}s.  Press Ctrl-C to stop.")

    try:
        while True:
            _log(f"Scanning {subnet} …")

            # ── Scan ──────────────────────────────────────────────────────
            try:
                from sentinel.scanner import scan  # local import keeps tests easy
                raw_devices = scan(subnet, iface=iface, timeout=timeout)
            except PermissionError as exc:
                print(f"[ERROR] {exc}", file=sys.stderr)
                # Permission errors won't fix themselves; stop the loop.
                return
            except Exception as exc:  # noqa: BLE001
                # Transient errors (network hiccup, interface blip): log and retry.
                print(f"[WARN] Scan failed: {exc}. Retrying in {interval}s.", file=sys.stderr)
                time.sleep(interval)
                continue

            # ── Classify ──────────────────────────────────────────────────
            classified = classifier.classify_devices(raw_devices, whitelist)

            known_count   = sum(1 for d in classified if d["status"] != STATUS_UNKNOWN)
            unknown_count = sum(1 for d in classified if d["status"] == STATUS_UNKNOWN)
            _log(f"Found {len(classified)} device(s): {known_count} known, {unknown_count} unknown.")

            # ── Deduplicate and alert ─────────────────────────────────────
            for device in classified:
                if device["status"] == STATUS_UNKNOWN:
                    mac = normalize_mac(device["mac"])
                    if mac not in alerted_macs:
                        # First time we've seen this MAC – alert.
                        alerted_macs.add(mac)
                        notify.alert(device["ip"], device["mac"])

            # ── Wait for the next scan interval ───────────────────────────
            time.sleep(interval)

    except KeyboardInterrupt:
        print()
        _log("Monitoring stopped by user.")
