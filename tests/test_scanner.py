"""
test_scanner.py – Unit tests for subnet validation and MAC normalization.

These tests import only the pure-Python parts of scanner.py (validate_subnet)
and whitelist.py (normalize_mac).  They never call scan() or import Scapy,
so they run without root privileges and without a network connection.
"""

import pytest
from sentinel.scanner import validate_subnet
from sentinel.whitelist import normalize_mac


# ---------------------------------------------------------------------------
# Subnet validation
# ---------------------------------------------------------------------------

class TestValidateSubnet:

    def test_valid_subnet_standard(self):
        """A correctly formed /24 subnet is accepted."""
        net = validate_subnet("192.168.29.0/24")
        assert str(net) == "192.168.29.0/24"

    def test_valid_subnet_host_bits_accepted(self):
        """192.168.29.5/24 is accepted and normalised to 192.168.29.0/24.

        This is a common mistake – users often type their own IP instead of
        the network address.  strict=False in IPv4Network silently zeros the
        host bits, which is friendlier behaviour.
        """
        net = validate_subnet("192.168.29.5/24")
        assert str(net) == "192.168.29.0/24"

    def test_valid_subnet_slash_16(self):
        net = validate_subnet("10.0.0.0/16")
        assert str(net) == "10.0.0.0/16"

    def test_invalid_subnet_bad_octets(self):
        """Octets out of range raise ValueError with a helpful message."""
        with pytest.raises(ValueError, match="Invalid subnet"):
            validate_subnet("999.999.0.0/24")

    def test_invalid_subnet_no_prefix(self):
        """A bare IP without /prefix raises ValueError."""
        with pytest.raises(ValueError, match="Invalid subnet"):
            validate_subnet("192.168.1.1")

    def test_invalid_subnet_nonsense_string(self):
        with pytest.raises(ValueError, match="Invalid subnet"):
            validate_subnet("not-a-subnet")

    def test_invalid_subnet_empty_string(self):
        with pytest.raises(ValueError, match="Invalid subnet"):
            validate_subnet("")


# ---------------------------------------------------------------------------
# MAC normalisation
# ---------------------------------------------------------------------------

class TestNormalizeMac:

    def test_lowercase_colon_unchanged(self):
        """Already-normalised MACs pass through unchanged."""
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"

    def test_uppercase_converted(self):
        """Uppercase letters are lowercased."""
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_dashes_converted_to_colons(self):
        """Windows-style dash separators are converted to colons."""
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    def test_mixed_case_dashes(self):
        """Mixed case with dashes is fully normalised."""
        assert normalize_mac("aA-Bb-cC-Dd-eE-Ff") == "aa:bb:cc:dd:ee:ff"

    def test_leading_trailing_whitespace_stripped(self):
        """Leading and trailing whitespace is stripped before parsing."""
        assert normalize_mac("  aa:bb:cc:dd:ee:ff  ") == "aa:bb:cc:dd:ee:ff"

    def test_invalid_too_short(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("aa:bb:cc:dd:ee")

    def test_invalid_too_long(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("aa:bb:cc:dd:ee:ff:00")

    def test_invalid_non_hex(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("zz:bb:cc:dd:ee:ff")

    def test_invalid_empty(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("")
