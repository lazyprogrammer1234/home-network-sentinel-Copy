"""
__main__.py – Entry point for the Home Network Sentinel.

Single-scan mode (Phase 1 behaviour, default):
    sudo venv/bin/python -m sentinel --subnet 192.168.29.0/24 --iface en0

Continuous monitoring mode (Phase 2):
    sudo venv/bin/python -m sentinel --subnet 192.168.29.0/24 --iface en0 --monitor
    sudo venv/bin/python -m sentinel --subnet 192.168.29.0/24 --iface en0 --monitor --interval 30

Discord alerts (optional):
    export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
    sudo venv/bin/python -m sentinel --subnet 192.168.29.0/24 --iface en0 --monitor

Key concept: main() is kept thin – it parses arguments, validates early,
and delegates all real work to the appropriate module.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinel import whitelist as wl_module
from sentinel import classifier
from sentinel import display


DEFAULT_WHITELIST = Path("whitelist.json")
DEFAULT_INTERVAL  = 60


def _build_parser() -> argparse.ArgumentParser:
    """Return the argument parser with formatting and examples."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=(
            "Home Network Sentinel: Local ARP network discovery, device classification, and intrusion alert tool.\n"
            "Only scan networks you own or have explicit authorization to monitor."
        ),
        epilog=(
            "examples:\n"
            "  # Run a single discovery scan (requires elevated privileges for ARP):\n"
            "  sudo venv/bin/python -m sentinel --subnet 192.168.1.0/24\n\n"
            "  # Specify network interface and custom device whitelist:\n"
            "  sudo venv/bin/python -m sentinel --subnet 192.168.1.0/24 --iface en0 --whitelist my_whitelist.json\n\n"
            "  # Continuous monitoring mode (scan every 30 seconds):\n"
            "  sudo venv/bin/python -m sentinel --subnet 192.168.1.0/24 --monitor --interval 30\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--subnet",
        required=True,
        help="IPv4 subnet to scan in CIDR notation, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Network interface to use, e.g. en0. Defaults to Scapy's choice.",
    )
    parser.add_argument(
        "--whitelist",
        default=str(DEFAULT_WHITELIST),
        help=f"Path to the whitelist JSON file. Default: {DEFAULT_WHITELIST}",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Seconds to wait for ARP replies per scan. Default: 2.0",
    )
    # ── Phase 2 additions ─────────────────────────────────────────────────
    parser.add_argument(
        "--monitor",
        action="store_true",
        default=False,
        help="Run in continuous monitoring mode (repeat scan at --interval seconds).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"Seconds between scans in monitoring mode. Default: {DEFAULT_INTERVAL}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, validate, and run in single-scan or monitoring mode."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ── Validate numeric arguments early (no privileges needed) ───────────
    if args.interval < 1:
        print("[ERROR] --interval must be at least 1 second.", file=sys.stderr)
        return 1

    if args.timeout <= 0:
        print("[ERROR] --timeout must be greater than 0 seconds.", file=sys.stderr)
        return 1

    # ── Load whitelist ────────────────────────────────────────────────────
    try:
        whitelist = wl_module.load_whitelist(args.whitelist)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    # ── Validate subnet (early, without needing root) ─────────────────────
    try:
        from sentinel.scanner import validate_subnet
        validate_subnet(args.subnet)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    # ── Dispatch to the right mode ────────────────────────────────────────
    if args.monitor:
        # Monitoring mode: loops until Ctrl-C.
        from sentinel.monitor import run_monitor
        run_monitor(
            subnet=args.subnet,
            whitelist=whitelist,
            interval=args.interval,
            iface=args.iface,
            timeout=args.timeout,
        )
        return 0

    # Single-scan mode (Phase 1 behaviour – unchanged).
    print(f"Scanning {args.subnet} …  (this may take a few seconds)")
    try:
        from sentinel.scanner import scan
        devices_raw = scan(args.subnet, iface=args.iface, timeout=args.timeout)
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.", file=sys.stderr)
        return 130
    except ImportError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    classified = classifier.classify_devices(devices_raw, whitelist)
    display.print_table(classified)
    return 0


if __name__ == "__main__":
    sys.exit(main())
