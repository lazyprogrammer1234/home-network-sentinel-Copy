"""
test_whitelist.py – Unit tests for whitelist loading and MAC lookup.

We use pytest's tmp_path fixture to create real temporary JSON files
so we test the actual file I/O without touching the project whitelist.
No network access or Scapy imports are needed.
"""

import json
import pytest
from sentinel.whitelist import load_whitelist, lookup, normalize_mac


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_whitelist(path, data):
    """Write *data* as JSON to *path* and return the path."""
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# load_whitelist
# ---------------------------------------------------------------------------

class TestLoadWhitelist:

    def test_loads_valid_whitelist(self, tmp_path):
        """A well-formed whitelist is loaded and MACs are normalised."""
        f = _write_whitelist(tmp_path / "wl.json", {
            "devices": [
                {"mac": "AA:BB:CC:DD:EE:FF", "name": "Router"},
                {"mac": "11:22:33:44:55:66", "name": "Laptop"},
            ]
        })
        result = load_whitelist(f)
        assert result == {
            "aa:bb:cc:dd:ee:ff": "Router",
            "11:22:33:44:55:66": "Laptop",
        }

    def test_loads_devices_without_names(self, tmp_path):
        """Devices without a 'name' field default to an empty string."""
        f = _write_whitelist(tmp_path / "wl.json", {
            "devices": [{"mac": "aa:bb:cc:dd:ee:ff"}]
        })
        result = load_whitelist(f)
        assert result["aa:bb:cc:dd:ee:ff"] == ""

    def test_loads_empty_device_list(self, tmp_path):
        """An empty devices list returns an empty dict (valid, not an error)."""
        f = _write_whitelist(tmp_path / "wl.json", {"devices": []})
        result = load_whitelist(f)
        assert result == {}

    def test_dash_separated_mac_normalised_on_load(self, tmp_path):
        """Dashes in whitelist MACs are normalised to colons at load time."""
        f = _write_whitelist(tmp_path / "wl.json", {
            "devices": [{"mac": "AA-BB-CC-DD-EE-FF", "name": "TV"}]
        })
        result = load_whitelist(f)
        assert "aa:bb:cc:dd:ee:ff" in result

    def test_missing_file_raises_file_not_found(self, tmp_path):
        missing = tmp_path / "does_not_exist.json"
        with pytest.raises(FileNotFoundError, match="Whitelist file not found"):
            load_whitelist(missing)

    def test_malformed_json_raises_value_error(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{ not valid json }", encoding="utf-8")
        with pytest.raises(ValueError, match="malformed"):
            load_whitelist(f)

    def test_missing_devices_key_raises_value_error(self, tmp_path):
        """JSON with no 'devices' key raises a clear ValueError."""
        f = _write_whitelist(tmp_path / "wl.json", {"hosts": []})
        with pytest.raises(ValueError, match="'devices' list"):
            load_whitelist(f)

    def test_entry_missing_mac_raises_value_error(self, tmp_path):
        """A device entry without a 'mac' field raises ValueError."""
        f = _write_whitelist(tmp_path / "wl.json", {
            "devices": [{"name": "No MAC here"}]
        })
        with pytest.raises(ValueError, match="missing the 'mac' field"):
            load_whitelist(f)


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------

class TestLookup:

    def _wl(self):
        """A small in-memory whitelist for lookup tests."""
        return {
            "aa:bb:cc:dd:ee:ff": "My Router",
            "11:22:33:44:55:66": "",
        }

    def test_known_mac_returns_true_and_name(self):
        is_known, name = lookup("aa:bb:cc:dd:ee:ff", self._wl())
        assert is_known is True
        assert name == "My Router"

    def test_known_mac_uppercase_input_still_matches(self):
        """lookup normalises the input MAC before comparing."""
        is_known, name = lookup("AA:BB:CC:DD:EE:FF", self._wl())
        assert is_known is True

    def test_known_mac_no_name_returns_empty_string(self):
        is_known, name = lookup("11:22:33:44:55:66", self._wl())
        assert is_known is True
        assert name == ""

    def test_unknown_mac_returns_false_and_empty_name(self):
        is_known, name = lookup("ff:ff:ff:ff:ff:ff", self._wl())
        assert is_known is False
        assert name == ""

    def test_lookup_empty_whitelist_always_unknown(self):
        is_known, name = lookup("aa:bb:cc:dd:ee:ff", {})
        assert is_known is False
