"""
test_classifier.py – Unit tests for device classification.

classify_devices() is a pure function (no I/O, no network).
These tests cover: known device, unknown device, multiple mixed devices,
and edge cases like an empty device list.
"""

import pytest
from sentinel.classifier import classify_devices, STATUS_KNOWN, STATUS_UNKNOWN


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def whitelist():
    """A small in-memory whitelist used across tests."""
    return {
        "aa:bb:cc:dd:ee:ff": "My Router",
        "11:22:33:44:55:66": "My Laptop",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestClassifyDevices:

    def test_known_device_labelled_correctly(self, whitelist):
        """A device whose MAC is in the whitelist gets status KNOWN."""
        devices = [{"ip": "192.168.29.1", "mac": "aa:bb:cc:dd:ee:ff"}]
        result = classify_devices(devices, whitelist)

        assert len(result) == 1
        assert result[0]["status"] == STATUS_KNOWN
        assert result[0]["name"] == "My Router"
        assert result[0]["ip"] == "192.168.29.1"
        assert result[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_unknown_device_labelled_correctly(self, whitelist):
        """A device whose MAC is NOT in the whitelist gets status UNKNOWN."""
        devices = [{"ip": "192.168.29.50", "mac": "de:ad:be:ef:00:01"}]
        result = classify_devices(devices, whitelist)

        assert result[0]["status"] == STATUS_UNKNOWN
        assert result[0]["name"] == ""

    def test_mixed_devices_classified_independently(self, whitelist):
        """Each device in a list is classified independently."""
        devices = [
            {"ip": "192.168.29.1",  "mac": "aa:bb:cc:dd:ee:ff"},  # known
            {"ip": "192.168.29.50", "mac": "de:ad:be:ef:00:01"},  # unknown
            {"ip": "192.168.29.10", "mac": "11:22:33:44:55:66"},  # known
        ]
        result = classify_devices(devices, whitelist)

        statuses = {d["ip"]: d["status"] for d in result}
        assert statuses["192.168.29.1"]  == STATUS_KNOWN
        assert statuses["192.168.29.50"] == STATUS_UNKNOWN
        assert statuses["192.168.29.10"] == STATUS_KNOWN

    def test_empty_device_list_returns_empty(self, whitelist):
        """No devices in → no devices out.  No errors raised."""
        result = classify_devices([], whitelist)
        assert result == []

    def test_classification_against_empty_whitelist(self):
        """With an empty whitelist every device is UNKNOWN."""
        devices = [
            {"ip": "192.168.29.1",  "mac": "aa:bb:cc:dd:ee:ff"},
            {"ip": "192.168.29.10", "mac": "11:22:33:44:55:66"},
        ]
        result = classify_devices(devices, {})
        assert all(d["status"] == STATUS_UNKNOWN for d in result)

    def test_uppercase_mac_in_device_still_matches(self, whitelist):
        """MAC from scanner may arrive in uppercase; classification still works."""
        devices = [{"ip": "192.168.29.1", "mac": "AA:BB:CC:DD:EE:FF"}]
        result = classify_devices(devices, whitelist)
        assert result[0]["status"] == STATUS_KNOWN

    def test_output_contains_all_required_keys(self, whitelist):
        """Every result dict must have ip, mac, name, and status."""
        devices = [{"ip": "192.168.29.1", "mac": "aa:bb:cc:dd:ee:ff"}]
        result = classify_devices(devices, whitelist)
        assert set(result[0].keys()) == {"ip", "mac", "name", "status"}
