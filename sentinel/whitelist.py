"""
whitelist.py – Load and query the JSON whitelist of known devices.

The whitelist is a simple JSON file structured like this:

    {
        "devices": [
            {"mac": "aa:bb:cc:dd:ee:ff", "name": "My Laptop"},
            {"mac": "11:22:33:44:55:66", "name": "Router"}
        ]
    }

Key concept: MAC addresses are stored and compared in a normalised form
(lowercase, colon-separated).  The user might type them with dashes or
uppercase – we handle that transparently.
"""

import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# MAC normalisation
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$", re.IGNORECASE)


def normalize_mac(mac: str) -> str:
    """Return a MAC address as lowercase colon-separated string.

    Examples
    --------
    >>> normalize_mac("AA-BB-CC-DD-EE-FF")
    'aa:bb:cc:dd:ee:ff'
    >>> normalize_mac("aa:bb:cc:dd:ee:ff")
    'aa:bb:cc:dd:ee:ff'
    """
    cleaned = mac.strip().lower().replace("-", ":")
    if not _MAC_RE.match(cleaned):
        raise ValueError(f"Invalid MAC address format: {mac!r}")
    return cleaned


# ---------------------------------------------------------------------------
# Whitelist loading
# ---------------------------------------------------------------------------

def load_whitelist(path: str | Path) -> dict[str, str]:
    """Load the whitelist JSON and return a dict of {normalised_mac: name}.

    Raises
    ------
    FileNotFoundError
        If the whitelist file does not exist.
    ValueError
        If the JSON is malformed or has an unexpected structure.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Whitelist file not found: {path}\n"
            "Create one with: cp whitelist.example.json whitelist.json"
        )

    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Whitelist JSON is malformed: {exc}") from exc

    if not isinstance(data, dict) or "devices" not in data:
        raise ValueError(
            "Whitelist JSON must have a top-level 'devices' list.\n"
            "See whitelist.example.json for the expected format."
        )

    devices: dict[str, str] = {}
    for i, entry in enumerate(data["devices"]):
        if "mac" not in entry:
            raise ValueError(f"Whitelist entry #{i} is missing the 'mac' field.")
        mac = normalize_mac(entry["mac"])
        name = entry.get("name", "")
        devices[mac] = name

    return devices


# ---------------------------------------------------------------------------
# Lookup helper
# ---------------------------------------------------------------------------

def lookup(mac: str, whitelist: dict[str, str]) -> tuple[bool, str]:
    """Check whether a MAC is in the whitelist.

    Returns
    -------
    (is_known, friendly_name)
        is_known     – True if the MAC is in the whitelist.
        friendly_name – The name from the whitelist, or "" if unknown.
    """
    normalised = normalize_mac(mac)
    if normalised in whitelist:
        return True, whitelist[normalised]
    return False, ""
