"""
classifier.py – Label each discovered device as KNOWN or UNKNOWN.

Key concept: This module is intentionally thin.  It takes the raw list
from the scanner and the dict from the whitelist and annotates each device.
Keeping classification separate from discovery means we can test it
without any network calls or Scapy imports.
"""

from __future__ import annotations

from sentinel.whitelist import lookup


# Status labels used throughout the project
STATUS_KNOWN = "KNOWN"
STATUS_UNKNOWN = "UNKNOWN"


def classify_devices(
    devices: list[dict],
    whitelist: dict[str, str],
) -> list[dict]:
    """Annotate each device dict with 'status' and 'name'.

    Parameters
    ----------
    devices:
        List of dicts with at least 'ip' and 'mac' keys.
        These come directly from scanner.scan().
    whitelist:
        Dict of {normalised_mac: friendly_name} from whitelist.load_whitelist().

    Returns
    -------
    A new list of dicts, each with keys: ip, mac, name, status.

    Example
    -------
    >>> wl = {"aa:bb:cc:dd:ee:ff": "My Laptop"}
    >>> classify_devices([{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"}], wl)
    [{'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'name': 'My Laptop', 'status': 'KNOWN'}]
    """
    results = []
    for device in devices:
        is_known, name = lookup(device["mac"], whitelist)
        results.append(
            {
                "ip": device["ip"],
                "mac": device["mac"],
                "name": name,
                "status": STATUS_KNOWN if is_known else STATUS_UNKNOWN,
            }
        )
    return results
