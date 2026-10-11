"""
test_notify.py – Unit tests for terminal alerts and Discord notifications.

Key testing technique: unittest.mock.patch
    We replace `requests.post` with a MagicMock before calling
    send_discord_alert().  This means:
    - No real HTTP request is ever made.
    - No real Discord webhook is ever contacted.
    - We can control exactly what the mock returns or raises.

    Because `requests` is now a module-level import in sentinel.notify,
    we patch it as "sentinel.notify.requests" – the name as it is bound
    in the module under test.

os.environ is also patched per-test so we can simulate the webhook URL
being set or unset without touching the actual environment.
"""

from __future__ import annotations

import os
from unittest.mock import patch, MagicMock

import pytest
import requests as real_requests  # used only to construct realistic exceptions

from sentinel.notify import (
    print_alert,
    send_discord_alert,
    alert,
    _ENV_VAR,
)


# ---------------------------------------------------------------------------
# Terminal alert
# ---------------------------------------------------------------------------

class TestPrintAlert:

    def test_print_alert_includes_ip_and_mac(self, capsys):
        """The terminal alert must contain the IP and MAC of the device."""
        print_alert("192.168.29.50", "de:ad:be:ef:00:01")
        captured = capsys.readouterr()
        assert "192.168.29.50" in captured.out
        assert "de:ad:be:ef:00:01" in captured.out

    def test_print_alert_includes_unknown_label(self, capsys):
        """The alert must make it obvious something unusual was detected."""
        print_alert("10.0.0.5", "aa:bb:cc:00:11:22")
        captured = capsys.readouterr()
        assert "UNKNOWN" in captured.out.upper()


# ---------------------------------------------------------------------------
# Discord – webhook configured
# ---------------------------------------------------------------------------

class TestSendDiscordAlert:

    def _mock_requests(self, status_code: int = 204) -> MagicMock:
        """Return a mock `requests` module whose .post() returns a fake response."""
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.raise_for_status = MagicMock()

        mock_req_module = MagicMock()
        mock_req_module.post.return_value = mock_resp
        return mock_req_module

    def test_sends_message_when_webhook_is_set(self):
        """When DISCORD_WEBHOOK_URL is set, requests.post is called once."""
        fake_url = "https://discord.com/api/webhooks/test/fake"
        mock_req = self._mock_requests(204)

        with (
            patch.dict(os.environ, {_ENV_VAR: fake_url}),
            patch("sentinel.notify.requests", mock_req),
        ):
            result = send_discord_alert("192.168.29.50", "de:ad:be:ef:00:01")

        assert result is True
        mock_req.post.assert_called_once()

        # Verify the payload contains the IP and MAC.
        call_kwargs = mock_req.post.call_args.kwargs
        payload = call_kwargs.get("json", {})
        assert "192.168.29.50" in payload["content"]
        assert "de:ad:be:ef:00:01" in payload["content"]

    def test_does_not_send_when_webhook_is_unset(self):
        """When DISCORD_WEBHOOK_URL is not set, requests.post is never called."""
        env_without_webhook = {k: v for k, v in os.environ.items() if k != _ENV_VAR}
        mock_req = self._mock_requests()

        with (
            patch.dict(os.environ, env_without_webhook, clear=True),
            patch("sentinel.notify.requests", mock_req),
        ):
            result = send_discord_alert("192.168.29.50", "de:ad:be:ef:00:01")

        assert result is False
        mock_req.post.assert_not_called()

    def test_returns_false_and_logs_on_http_error(self, capsys):
        """A non-2xx HTTP response is caught; returns False and logs a warning."""
        fake_url = "https://discord.com/api/webhooks/test/fake"

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = real_requests.HTTPError("400 Bad Request")

        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp

        with (
            patch.dict(os.environ, {_ENV_VAR: fake_url}),
            patch("sentinel.notify.requests", mock_req),
        ):
            result = send_discord_alert("192.168.29.50", "de:ad:be:ef:00:01")

        assert result is False
        captured = capsys.readouterr()
        assert "Discord notification failed" in captured.err

    def test_returns_false_and_logs_on_connection_error(self, capsys):
        """A network error (ConnectionError) is caught; returns False and logs."""
        fake_url = "https://discord.com/api/webhooks/test/fake"

        mock_req = MagicMock()
        mock_req.post.side_effect = real_requests.ConnectionError("unreachable")

        with (
            patch.dict(os.environ, {_ENV_VAR: fake_url}),
            patch("sentinel.notify.requests", mock_req),
        ):
            result = send_discord_alert("192.168.29.50", "de:ad:be:ef:00:01")

        assert result is False
        captured = capsys.readouterr()
        assert "Discord notification failed" in captured.err

    def test_webhook_url_not_logged_on_error(self, capsys):
        """The webhook URL must NEVER appear in error output (security check)."""
        fake_url = "https://discord.com/api/webhooks/super_secret/token"

        mock_req = MagicMock()
        mock_req.post.side_effect = Exception("boom")

        with (
            patch.dict(os.environ, {_ENV_VAR: fake_url}),
            patch("sentinel.notify.requests", mock_req),
        ):
            send_discord_alert("192.168.29.50", "de:ad:be:ef:00:01")

        captured = capsys.readouterr()
        assert fake_url not in captured.out
        assert fake_url not in captured.err

    def test_webhook_url_redacted_when_present_in_exception(self, capsys):
        """Even if the exception string includes the webhook URL, it is redacted."""
        fake_url = "https://discord.com/api/webhooks/12345/secret_token"

        mock_req = MagicMock()
        mock_req.post.side_effect = real_requests.HTTPError(
            f"404 Client Error: Not Found for url: {fake_url}"
        )

        with (
            patch.dict(os.environ, {_ENV_VAR: fake_url}),
            patch("sentinel.notify.requests", mock_req),
        ):
            result = send_discord_alert("192.168.29.50", "de:ad:be:ef:00:01")

        assert result is False
        captured = capsys.readouterr()
        assert fake_url not in captured.err
        assert "[REDACTED_WEBHOOK_URL]" in captured.err


# ---------------------------------------------------------------------------
# Combined alert()
# ---------------------------------------------------------------------------

class TestAlert:

    def test_alert_calls_print_alert_and_discord(self):
        """alert() calls both print_alert and send_discord_alert."""
        with (
            patch("sentinel.notify.print_alert") as mock_print,
            patch("sentinel.notify.send_discord_alert") as mock_discord,
        ):
            alert("10.0.0.1", "aa:bb:cc:dd:ee:ff")

        mock_print.assert_called_once_with("10.0.0.1", "aa:bb:cc:dd:ee:ff")
        mock_discord.assert_called_once_with("10.0.0.1", "aa:bb:cc:dd:ee:ff")

    def test_alert_continues_when_discord_fails(self):
        """alert() does not raise even if send_discord_alert returns False."""
        with (
            patch("sentinel.notify.print_alert"),
            patch("sentinel.notify.send_discord_alert", return_value=False),
        ):
            # Should not raise.
            alert("10.0.0.1", "aa:bb:cc:dd:ee:ff")
