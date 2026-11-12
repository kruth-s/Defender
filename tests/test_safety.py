"""
Unit tests for BEAP SSRF boundary enforcement and safe crawler.
"""

import pytest
from beap.safety import is_safe_target_url
from beap.crawler import BrowserProbe


def test_ssrf_direct_targets():
    # Loopback
    safe, msg = is_safe_target_url("http://127.0.0.1:8080/admin")
    assert not safe
    assert "loopback" in msg.lower() or "prohibited" in msg.lower()

    safe, msg = is_safe_target_url("http://localhost:3000")
    assert not safe
    assert "prohibited" in msg.lower()

    # Private RFC 1918
    safe, msg = is_safe_target_url("http://10.0.1.5/internal")
    assert not safe
    assert "private" in msg.lower()

    safe, msg = is_safe_target_url("http://192.168.1.1/setup.cgi")
    assert not safe
    assert "private" in msg.lower()

    safe, msg = is_safe_target_url("http://172.16.5.20/db")
    assert not safe
    assert "private" in msg.lower()

    # Cloud metadata
    safe, msg = is_safe_target_url("http://169.254.169.254/latest/meta-data/")
    assert not safe
    assert "link-local" in msg.lower() or "prohibited" in msg.lower()

    safe, msg = is_safe_target_url("http://metadata.google.internal")
    assert not safe
    assert "prohibited" in msg.lower()

    # Schemes
    safe, msg = is_safe_target_url("file:///etc/passwd")
    assert not safe
    assert "scheme" in msg.lower()

    safe, msg = is_safe_target_url("gopher://127.0.0.1:6379/_")
    assert not safe
    assert "scheme" in msg.lower()


def test_ssrf_dns_fail_closed():
    # Live fail_closed mode rejects unresolvable invalid domain
    safe, msg = is_safe_target_url("http://this-domain-definitely-does-not-exist-xyz123987.invalid/", fail_closed=True)
    assert not safe
    assert "failed" in msg.lower()

    # Offline permitted mode allows for mock inspection
    safe, msg = is_safe_target_url("http://this-domain-definitely-does-not-exist-xyz123987.invalid/", fail_closed=False)
    assert safe
    assert "offline" in msg.lower()


def test_crawler_probe_blocks_ssrf():
    probe = BrowserProbe()

    # Direct SSRF target
    res = probe.probe_url("http://127.0.0.1:9000/status")
    assert res.ssrf_blocked is True
    assert res.status_code == 0
    assert "ssrf" in res.error_message.lower() or "prohibited" in res.error_message.lower()

    # Private target
    res = probe.probe_url("http://10.200.1.10/admin")
    assert res.ssrf_blocked is True
    assert res.status_code == 0

