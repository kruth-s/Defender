"""
Browser and Network Probe Module.
Performs live dynamic page retrieval, HTTP header inspection, SSL certificate
verification, redirect tracking, and active input probe sanity checking
with built-in SSRF protection.
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import requests
import urllib3

from beap.safety import is_safe_target_url

# Suppress insecure request warnings for hostile or self-signed probe targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

ACTIVE_PROBE_TOKEN = "beap_sanity_check_9182"


class PageProbeResult:
    """Container for dynamic artifacts retrieved during webpage inspection."""

    def __init__(
        self,
        url: str,
        final_url: str = "",
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        html_content: str = "",
        cookies: Optional[List[Dict[str, Any]]] = None,
        tls_info: Optional[Dict[str, Any]] = None,
        redirect_history: Optional[List[str]] = None,
        reflection_probe: str = "",
        reflection_detected: bool = False,
        error_message: str = "",
        ssrf_blocked: bool = False
    ):
        self.url = url
        self.final_url = final_url or url
        self.status_code = status_code
        self.headers = headers or {}
        self.html_content = html_content
        self.cookies = cookies or []
        self.tls_info = tls_info or {"cert_valid": True, "longevity_days": 365.0, "issuer_name": ""}
        self.redirect_history = redirect_history or []
        self.reflection_probe = reflection_probe
        self.reflection_detected = reflection_detected
        self.error_message = error_message
        self.ssrf_blocked = ssrf_blocked


class BrowserProbe:
    """
    Defensive network probe for observing HTTP transport headers, TLS certificates,
    and controlled form input behavior.
    """

    def __init__(self, timeout: float = 6.0, user_agent: str = DEFAULT_USER_AGENT):
        self.timeout = timeout
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

    def probe_tls_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Directly probes SSL/TLS certificate via socket connection."""
        tls_info = {
            "cert_valid": False,
            "longevity_days": 0.0,
            "issuer_name": "Unknown",
            "subject_alt_names": []
        }
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_info["cert_valid"] = True

                    not_after_str = cert.get("notAfter", "")
                    if not_after_str:
                        exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (exp_date - now).total_seconds() / 86400.0
                        tls_info["longevity_days"] = max(0.0, days_left)

                    issuer_parts = []
                    for item in cert.get("issuer", ()):
                        for k, v in item:
                            if k in ["organizationName", "commonName"]:
                                issuer_parts.append(v)
                    tls_info["issuer_name"] = " ".join(issuer_parts)

                    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                    tls_info["subject_alt_names"] = sans
        except ssl.SSLCertVerificationError as e:
            tls_info["cert_valid"] = False
            tls_info["issuer_name"] = f"Untrusted / Self-signed: {str(e)}"
        except Exception as e:
            tls_info["cert_valid"] = False
            tls_info["issuer_name"] = f"Handshake failed: {str(e)}"

        return tls_info

    def test_reflection_probe(self, base_url: str, form_action: str = "") -> bool:
        """
        Actively checks whether an input probe token is echoed unsanitized.
        Uses a benign non-executable alphanumeric probe.
        """
        target_endpoint = urljoin(base_url, form_action) if form_action else base_url
        is_safe, reason = is_safe_target_url(target_endpoint)
        if not is_safe:
            return False

        try:
            # Test GET query reflection
            probe_param = {"beap_test": ACTIVE_PROBE_TOKEN}
            r = self.session.get(target_endpoint, params=probe_param, timeout=3.0, verify=False)
            if ACTIVE_PROBE_TOKEN in r.text:
                return True
        except Exception:
            pass
        return False

    def probe_url(self, url: str, test_reflection: bool = False) -> PageProbeResult:
        """
        Executes HTTP request, fetches headers, HTML, cookies, and TLS certificate.
        Enforces SSRF boundary checks on both target and redirect chain.
        """
        # SSRF Pre-flight Check
        is_safe, reason = is_safe_target_url(url)
        if not is_safe:
            return PageProbeResult(
                url=url,
                status_code=0,
                error_message=reason,
                ssrf_blocked=True
            )

        parsed = urlparse(url)
        scheme = parsed.scheme.lower() or "http"
        hostname = parsed.hostname or ""

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )

            # Validate redirect chain for SSRF
            redirect_chain = [r.url for r in resp.history] + [resp.url]
            for hop in redirect_chain:
                hop_safe, hop_reason = is_safe_target_url(hop)
                if not hop_safe:
                    return PageProbeResult(
                        url=url,
                        status_code=0,
                        error_message=f"SSRF Protection blocked redirect hop: {hop_reason}",
                        ssrf_blocked=True
                    )

            # TLS probe if HTTPS
            tls_data = {"cert_valid": True, "longevity_days": 365.0, "issuer_name": ""}
            if scheme == "https" and hostname:
                tls_data = self.probe_tls_certificate(hostname, port=443)

            # Cookies
            cookie_list = []
            for c in resp.cookies:
                cookie_list.append({
                    "name": c.name,
                    "secure": getattr(c, "secure", False),
                    "httponly": "httponly" in getattr(c, "_rest", {}),
                    "samesite": getattr(c, "_rest", {}).get("samesite", "")
                })

            reflection_detected = False
            if test_reflection:
                reflection_detected = self.test_reflection_probe(resp.url)

            return PageProbeResult(
                url=url,
                final_url=resp.url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                html_content=resp.text,
                cookies=cookie_list,
                tls_info=tls_data,
                redirect_history=redirect_chain,
                reflection_probe=ACTIVE_PROBE_TOKEN if test_reflection else "",
                reflection_detected=reflection_detected
            )

        except Exception as ex:
            return PageProbeResult(
                url=url,
                status_code=0,
                error_message=str(ex)
            )
