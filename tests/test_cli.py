"""
test_cli.py – Unit tests for command-line interface parsing and error handling.

Tests verify argument validation, missing inputs, and control flow in main()
without requiring real network scans, Scapy, or root permissions.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock
import pytest

from sentinel.__main__ import main, _build_parser


class TestCliParser:

    def test_parser_requires_subnet(self):
        """Omitting --subnet raises a SystemExit from argparse."""
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_parser_defaults(self):
        """Default arguments match expected values."""
        parser = _build_parser()
        args = parser.parse_args(["--subnet", "192.168.1.0/24"])
        assert args.subnet == "192.168.1.0/24"
        assert args.iface is None
        assert args.whitelist == "whitelist.json"
        assert args.timeout == 2.0
        assert args.monitor is False
        assert args.interval == 60


class TestMainValidation:

    def test_invalid_interval_returns_error(self, capsys):
        """Interval less than 1 second returns code 1."""
        ret = main(["--subnet", "192.168.1.0/24", "--interval", "0"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "--interval must be at least 1 second" in captured.err

    def test_invalid_timeout_returns_error(self, capsys):
        """Timeout of 0 or negative returns code 1."""
        ret = main(["--subnet", "192.168.1.0/24", "--timeout", "0"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "--timeout must be greater than 0" in captured.err

    def test_missing_whitelist_file_returns_error(self, capsys):
        """Non-existent whitelist file returns code 1 with clean error message."""
        ret = main(["--subnet", "192.168.1.0/24", "--whitelist", "non_existent_file.json"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Whitelist file not found" in captured.err

    def test_invalid_subnet_returns_error(self, tmp_path, capsys):
        """Invalid subnet returns code 1."""
        # Create a valid temporary whitelist
        wl_path = tmp_path / "wl.json"
        wl_path.write_text('{"devices": []}')

        ret = main(["--subnet", "999.999.999.0/24", "--whitelist", str(wl_path)])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Invalid subnet" in captured.err


class TestMainExecution:

    def test_single_scan_dispatch(self, tmp_path):
        """Single scan runs scan, classify, and display cleanly."""
        wl_path = tmp_path / "wl.json"
        wl_path.write_text('{"devices": []}')

        with (
            patch("sentinel.scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"}]) as mock_scan,
            patch("sentinel.display.print_table") as mock_table,
        ):
            ret = main(["--subnet", "192.168.1.0/24", "--whitelist", str(wl_path)])

        assert ret == 0
        mock_scan.assert_called_once()
        mock_table.assert_called_once()

    def test_monitor_dispatch(self, tmp_path):
        """Passing --monitor calls run_monitor."""
        wl_path = tmp_path / "wl.json"
        wl_path.write_text('{"devices": []}')

        with patch("sentinel.monitor.run_monitor") as mock_monitor:
            ret = main(["--subnet", "192.168.1.0/24", "--whitelist", str(wl_path), "--monitor"])

        assert ret == 0
        mock_monitor.assert_called_once()

    def test_single_scan_keyboard_interrupt(self, tmp_path, capsys):
        """KeyboardInterrupt during single scan exits with code 130 and message."""
        wl_path = tmp_path / "wl.json"
        wl_path.write_text('{"devices": []}')

        with patch("sentinel.scanner.scan", side_effect=KeyboardInterrupt):
            ret = main(["--subnet", "192.168.1.0/24", "--whitelist", str(wl_path)])

        assert ret == 130
        captured = capsys.readouterr()
        assert "Scan interrupted by user" in captured.err
