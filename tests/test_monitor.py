"""
test_monitor.py – Unit tests for the monitoring loop.

Strategy: we never call the real scanner.scan() or time.sleep().

Mocking approach (important for understanding):
    run_monitor() does `from sentinel.scanner import scan` inside the loop.
    When Python executes `from sentinel.scanner import scan`, it looks up
    `scan` in the `sentinel.scanner` module.  So we patch it there:
        patch("sentinel.scanner.scan", ...)
    This intercepts the lookup before the local name is bound, which is the
    reliable way to mock a function imported with `from ... import`.

All tests run without root, without a network, and without Discord.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock, call

import pytest

from sentinel.monitor import run_monitor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

WHITELIST = {"aa:bb:cc:dd:ee:ff": "My Router"}

KNOWN_DEVICE   = {"ip": "192.168.29.1",  "mac": "aa:bb:cc:dd:ee:ff"}
UNKNOWN_DEVICE = {"ip": "192.168.29.50", "mac": "de:ad:be:ef:00:01"}


def _make_scan_side_effect(*scan_results):
    """Return a side_effect list that yields each result in turn, then stops.

    We append a KeyboardInterrupt at the end so run_monitor() exits cleanly
    after consuming all the supplied scan results.
    """
    results = list(scan_results)
    results.append(KeyboardInterrupt())
    return results


# ---------------------------------------------------------------------------
# New-device detection
# ---------------------------------------------------------------------------

class TestNewDeviceDetection:

    def test_unknown_device_triggers_alert(self):
        """An unknown MAC that is not in the whitelist produces an alert."""
        side_effect = _make_scan_side_effect([UNKNOWN_DEVICE])

        with (
            patch("sentinel.scanner.scan", side_effect=side_effect),
            patch("sentinel.monitor.time.sleep"),
            patch("sentinel.notify.alert") as mock_alert,
        ):
            run_monitor("192.168.29.0/24", WHITELIST, interval=1)

        mock_alert.assert_called_once_with(
            UNKNOWN_DEVICE["ip"], UNKNOWN_DEVICE["mac"]
        )

    def test_known_device_does_not_trigger_alert(self):
        """A MAC that is in the whitelist never triggers an alert."""
        side_effect = _make_scan_side_effect([KNOWN_DEVICE])

        with (
            patch("sentinel.scanner.scan", side_effect=side_effect),
            patch("sentinel.monitor.time.sleep"),
            patch("sentinel.notify.alert") as mock_alert,
        ):
            run_monitor("192.168.29.0/24", WHITELIST, interval=1)

        mock_alert.assert_not_called()

    def test_empty_scan_result_produces_no_alert(self):
        """An empty scan (no devices found) produces no alerts."""
        side_effect = _make_scan_side_effect([])

        with (
            patch("sentinel.scanner.scan", side_effect=side_effect),
            patch("sentinel.monitor.time.sleep"),
            patch("sentinel.notify.alert") as mock_alert,
        ):
            run_monitor("192.168.29.0/24", WHITELIST, interval=1)

        mock_alert.assert_not_called()


# ---------------------------------------------------------------------------
# Alert deduplication
# ---------------------------------------------------------------------------

class TestAlertDeduplication:

    def test_same_unknown_mac_alerted_only_once(self):
        """The same unknown MAC appearing in two consecutive scans is alerted only once."""
        # Two scans, both returning the same unknown device.
        side_effect = _make_scan_side_effect(
            [UNKNOWN_DEVICE],
            [UNKNOWN_DEVICE],
        )

        with (
            patch("sentinel.scanner.scan", side_effect=side_effect),
            patch("sentinel.monitor.time.sleep"),
            patch("sentinel.notify.alert") as mock_alert,
        ):
            run_monitor("192.168.29.0/24", WHITELIST, interval=1)

        # Alert must fire exactly once despite two scans.
        mock_alert.assert_called_once()

    def test_two_different_unknown_macs_each_alerted_once(self):
        """Two different unknown MACs each get their own alert, once each."""
        device_b = {"ip": "192.168.29.51", "mac": "ca:fe:ba:be:00:01"}
        # Scan 1: first unknown; Scan 2: both unknowns.
        side_effect = _make_scan_side_effect(
            [UNKNOWN_DEVICE],
            [UNKNOWN_DEVICE, device_b],
        )

        with (
            patch("sentinel.scanner.scan", side_effect=side_effect),
            patch("sentinel.monitor.time.sleep"),
            patch("sentinel.notify.alert") as mock_alert,
        ):
            run_monitor("192.168.29.0/24", WHITELIST, interval=1)

        assert mock_alert.call_count == 2
        alerted_macs = {c.args[1] for c in mock_alert.call_args_list}
        assert UNKNOWN_DEVICE["mac"] in alerted_macs
        assert device_b["mac"] in alerted_macs

    def test_device_disappears_and_reappears_not_re_alerted(self):
        """A device that leaves and comes back is NOT re-alerted (session dedup)."""
        side_effect = _make_scan_side_effect(
            [UNKNOWN_DEVICE],   # Scan 1: unknown device seen → alert
            [],                  # Scan 2: device gone
            [UNKNOWN_DEVICE],   # Scan 3: device back → NO new alert
        )

        with (
            patch("sentinel.scanner.scan", side_effect=side_effect),
            patch("sentinel.monitor.time.sleep"),
            patch("sentinel.notify.alert") as mock_alert,
        ):
            run_monitor("192.168.29.0/24", WHITELIST, interval=1)

        # Only one alert for the entire session.
        mock_alert.assert_called_once()


# ---------------------------------------------------------------------------
# Scan failure handling
# ---------------------------------------------------------------------------

class TestScanFailureHandling:

    def test_transient_scan_error_is_logged_and_loop_continues(self, capsys):
        """A RuntimeError on one scan is logged and the loop retries."""
        side_effect = _make_scan_side_effect(
            RuntimeError("interface hiccup"),   # Scan 1: fails
            [KNOWN_DEVICE],                      # Scan 2: succeeds
        )

        with (
            patch("sentinel.scanner.scan", side_effect=side_effect),
            patch("sentinel.monitor.time.sleep"),
            patch("sentinel.notify.alert") as mock_alert,
        ):
            run_monitor("192.168.29.0/24", WHITELIST, interval=1)

        # No alert because the only real device is KNOWN.
        mock_alert.assert_not_called()

        # The warning should appear in stderr.
        captured = capsys.readouterr()
        assert "Scan failed" in captured.err

    def test_permission_error_stops_loop(self, capsys):
        """A PermissionError stops the monitoring loop immediately."""
        side_effect = _make_scan_side_effect(
            PermissionError("need root"),
        )

        with (
            patch("sentinel.scanner.scan", side_effect=side_effect),
            patch("sentinel.monitor.time.sleep"),
            patch("sentinel.notify.alert") as mock_alert,
        ):
            run_monitor("192.168.29.0/24", WHITELIST, interval=1)

        mock_alert.assert_not_called()
        captured = capsys.readouterr()
        assert "root" in captured.err.lower() or "permission" in captured.err.lower()
