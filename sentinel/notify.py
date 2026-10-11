"""
notify.py – Send alerts for newly discovered unknown devices.

Key concept: Notifications are separated from the monitoring loop so that
each delivery channel (terminal, Discord) can be tested in isolation and
a failure in one channel never affects the others.

Discord webhook:
    Set the environment variable DISCORD_WEBHOOK_URL to your webhook URL.
    If the variable is unset, only the terminal alert is printed.
    The URL is read at call-time (not at import-time) so tests can patch
    os.environ without needing to restart the interpreter.

Security note:
    Never hard-code the webhook URL.  Never log it.  The only place it
    appears is in the environment variable you set yourself.

Mocking note (for students reading the tests):
    `requests` is imported at module level so that tests can replace it with
    `patch("sentinel.notify.requests")`.  If it were imported inside the
    function, `patch` would not be able to intercept it.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

import requests  # top-level import – required for patch("sentinel.notify.requests")


# ---------------------------------------------------------------------------
# Terminal alert
# ---------------------------------------------------------------------------

def _timestamp() -> str:
    """Return the current local time as a short readable string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def print_alert(ip: str, mac: str) -> None:
    """Print a clearly visible terminal alert for an unknown device."""
    ts = _timestamp()
    print(f"\n{'=' * 60}")
    print(f"  ⚠  UNKNOWN DEVICE DETECTED  [{ts}]")
    print(f"  IP  : {ip}")
    print(f"  MAC : {mac}")
    print(f"{'=' * 60}\n")


# ---------------------------------------------------------------------------
# Discord webhook
# ---------------------------------------------------------------------------

_ENV_VAR = "DISCORD_WEBHOOK_URL"


def _get_webhook_url() -> str | None:
    """Return the Discord webhook URL from the environment, or None."""
    return os.environ.get(_ENV_VAR)


def send_discord_alert(ip: str, mac: str) -> bool:
    """Post an alert to the Discord webhook if one is configured.

    Returns True if the message was sent successfully, False otherwise.
    Never raises – a delivery failure is logged to stderr and the caller
    continues normally.

    Parameters
    ----------
    ip:  IP address of the unknown device.
    mac: MAC address of the unknown device.
    """
    url = _get_webhook_url()
    if not url:
        # Webhook not configured – silently skip.
        return False

    ts = _timestamp()
    payload = {
        "content": (
            f"⚠️ **Unknown device detected** `{ts}`\n"
            f"**IP :** `{ip}`\n"
            f"**MAC:** `{mac}`"
        )
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        # Log the error without revealing the webhook URL.
        err_msg = str(exc)
        if url and url in err_msg:
            err_msg = err_msg.replace(url, "[REDACTED_WEBHOOK_URL]")
        print(
            f"[WARN] Discord notification failed: {type(exc).__name__}: {err_msg}",
            file=sys.stderr,
        )
        return False


# ---------------------------------------------------------------------------
# Combined alert (terminal + optional Discord)
# ---------------------------------------------------------------------------

def alert(ip: str, mac: str) -> None:
    """Issue a terminal alert and, if configured, a Discord notification.

    This is the single function the monitoring loop calls.
    """
    print_alert(ip, mac)
    send_discord_alert(ip, mac)
