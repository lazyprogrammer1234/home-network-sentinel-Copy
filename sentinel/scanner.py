"""
scanner.py – Discover devices on a subnet using ARP requests.

Key concept: ARP (Address Resolution Protocol) is a Layer-2 protocol.
When we broadcast an ARP "who has <IP>?" packet to the whole subnet, every
device that is awake and on the same segment replies with its MAC address.
This is reliable and fast for local discovery.

Limitation: ARP only reaches devices on the same Layer-2 broadcast domain.
Devices on other subnets, VLANs, or that are powered off will not appear.

Elevated privileges: Scapy must craft and send raw Ethernet frames.
On macOS/Linux this requires root.  The rest of the application (whitelist
loading, classification, display, and all unit tests) does NOT need root.
We keep privilege use confined to this module.
"""

from __future__ import annotations

import ipaddress
import sys


# ---------------------------------------------------------------------------
# Subnet validation (no Scapy needed – safe to import/test without root)
# ---------------------------------------------------------------------------

def validate_subnet(subnet: str) -> ipaddress.IPv4Network:
    """Parse and validate an IPv4 subnet string.

    Returns an IPv4Network object if valid, raises ValueError otherwise.

    We use strict=False so that "192.168.1.5/24" is accepted and treated
    as "192.168.1.0/24" (the host bits are silently zeroed).

    Examples
    --------
    >>> validate_subnet("192.168.29.0/24")
    IPv4Network('192.168.29.0/24')
    >>> validate_subnet("192.168.29.5/24")   # host bits – accepted
    IPv4Network('192.168.29.0/24')
    """
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(
            f"Invalid subnet {subnet!r}. "
            "Expected format: 192.168.1.0/24"
        ) from exc

    # A bare IP like "192.168.1.1" is silently parsed as a /32 host route.
    # That is almost always a user mistake (forgot the /24), so we reject it.
    if "/" not in subnet:
        raise ValueError(
            f"Invalid subnet {subnet!r}: no prefix length specified. "
            "Expected format: 192.168.1.0/24"
        )

    return network


# ---------------------------------------------------------------------------
# ARP scan (requires Scapy and root/admin privileges at runtime)
# ---------------------------------------------------------------------------

def scan(subnet: str, iface: str | None = None, timeout: float = 2.0) -> list[dict]:
    """Send ARP requests to every host in *subnet* and collect replies.

    Parameters
    ----------
    subnet:
        IPv4 subnet in CIDR notation, e.g. "192.168.29.0/24".
    iface:
        Network interface name (e.g. "en0").  If None, Scapy picks one.
    timeout:
        Seconds to wait for ARP replies after the last packet is sent.

    Returns
    -------
    List of dicts: [{"ip": "...", "mac": "..."}]
    Each MAC is normalised to lowercase colon-separated form.

    Raises
    ------
    ValueError
        If the subnet string is invalid.
    PermissionError
        If the process lacks the privileges to send raw packets.
    ImportError
        If Scapy is not installed.
    RuntimeError
        If Scapy reports an interface or network error.
    """
    # Validate first – no privileges needed for this step.
    network = validate_subnet(subnet)

    # Import Scapy inside the function so that the rest of the codebase
    # (whitelist, classifier, display, tests) can be imported without Scapy.
    try:
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
        from scapy.error import Scapy_Exception      # type: ignore
    except ImportError as exc:
        raise ImportError(
            "Scapy is not installed.  Install it with:\n"
            "  venv/bin/pip install scapy==2.8.0"
        ) from exc

    # Suppress Scapy's verbose output (it prints a lot by default).
    conf.verb = 0

    # Build an Ethernet broadcast frame carrying an ARP "who-has" request.
    # Ether(dst="ff:ff:ff:ff:ff:ff") – broadcast to everyone on the segment.
    # ARP(pdst=str(network))         – ask for all IPs in the subnet.
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))

    kwargs: dict = {"timeout": timeout, "verbose": False}
    if iface:
        kwargs["iface"] = iface

    try:
        answered, _ = srp(packet, **kwargs)
    except PermissionError as exc:
        raise PermissionError(
            "Sending ARP packets requires root privileges.\n"
            "Re-run the scanner with:  sudo venv/bin/python -m sentinel.scanner"
        ) from exc
    except OSError as exc:
        # Catches "No such device" and similar interface errors.
        raise RuntimeError(
            f"Network error while scanning ({exc}).  "
            "Check that the interface name is correct and the network is up."
        ) from exc
    except Exception as exc:   # noqa: BLE001
        raise RuntimeError(f"Unexpected Scapy error: {exc}") from exc

    results: list[dict] = []
    for sent, received in answered:
        results.append(
            {
                "ip": received.psrc,
                "mac": received.hwsrc.lower(),
            }
        )

    return results
