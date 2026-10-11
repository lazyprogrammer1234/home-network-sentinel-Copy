"""
display.py – Render the classified device list as a readable terminal table.

Key concept: We build this with plain Python string formatting rather than
a third-party library (e.g. tabulate) to keep dependencies minimal and make
the output easy to understand.

ANSI escape codes add colour on supported terminals.  They are stripped
automatically when stdout is not a TTY (e.g. piped to a file).
"""

from __future__ import annotations

import sys

from sentinel.classifier import STATUS_KNOWN, STATUS_UNKNOWN


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_RED   = "\033[91m"
_GREEN = "\033[92m"
_BOLD  = "\033[1m"


def _colour(text: str, code: str) -> str:
    """Wrap *text* in an ANSI colour code, but only when stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{code}{text}{_RESET}"
    return text


# ---------------------------------------------------------------------------
# Table renderer
# ---------------------------------------------------------------------------

def print_table(devices: list[dict]) -> None:
    """Print a formatted table of classified devices to stdout.

    Each row shows: IP address, MAC address, friendly name, status.

    Parameters
    ----------
    devices:
        Output from classifier.classify_devices() – each dict must have
        keys: ip, mac, name, status.
    """
    if not devices:
        print("No devices found.  Check the subnet, interface, and try again.")
        return

    # Column widths – we compute them from the data so the table fits neatly.
    col_ip     = max(len("IP Address"),  max(len(d["ip"])   for d in devices))
    col_mac    = max(len("MAC Address"), max(len(d["mac"])  for d in devices))
    col_name   = max(len("Name"),        max(len(d["name"]) for d in devices))
    col_status = len("Status")

    sep = (
        f"+-{'-' * col_ip}-+-{'-' * col_mac}-+-{'-' * col_name}-+-{'-' * col_status}-+"
    )
    header = (
        f"| {'IP Address':<{col_ip}} "
        f"| {'MAC Address':<{col_mac}} "
        f"| {'Name':<{col_name}} "
        f"| {'Status':<{col_status}} |"
    )

    print()
    print(_colour(sep, _BOLD))
    print(_colour(header, _BOLD))
    print(_colour(sep, _BOLD))

    for device in sorted(devices, key=lambda d: _ip_sort_key(d["ip"])):
        status = device["status"]
        status_coloured = (
            _colour(STATUS_KNOWN,   _GREEN) if status == STATUS_KNOWN
            else _colour(STATUS_UNKNOWN, _RED)
        )
        print(
            f"| {device['ip']:<{col_ip}} "
            f"| {device['mac']:<{col_mac}} "
            f"| {device['name']:<{col_name}} "
            f"| {status_coloured:<{col_status}} |"
        )

    print(_colour(sep, _BOLD))
    print()

    known_count   = sum(1 for d in devices if d["status"] == STATUS_KNOWN)
    unknown_count = sum(1 for d in devices if d["status"] == STATUS_UNKNOWN)
    print(f"Devices found: {len(devices)}  |  Known: {known_count}  |  Unknown: {unknown_count}")
    print()


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    """Convert an IP string to a tuple of ints for natural sort order."""
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (0, 0, 0, 0)
