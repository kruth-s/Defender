"""
Dynamic Browser Evidence Extractor.
Extracts HTTP security headers, SSL/TLS certificate indicators,
and DOM/form dynamic behavior signals.
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import tldextract
from bs4 import BeautifulSoup

EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)

from beap.config import DYNAMIC_BROWSER_FEATURES

# Common short-lived or free automated certificate authority signatures
FREE_SHORT_LIVED_CAS = ["let's encrypt", "zerossl", "cpanel", "cloudflare", "free ssl", "self-signed"]


def parse_csp_directives(csp_header: str) -> Dict[str, List[str]]:
    """Parses a Content-Security-Policy header into directive -> tokens mapping."""
    directives: Dict[str, List[str]] = {}
    if not csp_header:
        return directives
    for part in csp_header.split(";"):
        tokens = part.strip().split()
        if tokens:
            directive_name = tokens[0].lower()
            directives[directive_name] = tokens[1:]
    return directives


def extract_header_evidence(headers: Dict[str, str], cookies: Optional[List[Dict[str, Any]]] = None) -> Dict[str, float]:
    """
    Extracts security header indicators from an HTTP response header dictionary.
    Case-insensitive matching for all HTTP headers.
    """
    norm_headers = {k.lower(): str(v) for k, v in headers.items()}
    evidence: Dict[str, float] = {}

    # 1. HSTS
    hsts = norm_headers.get("strict-transport-security", "")
    has_hsts = 1.0 if hsts else 0.0
    evidence["has_hsts"] = has_hsts

    max_age_adequate = 0.0
    if has_hsts:
        match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if match:
            max_age_val = int(match.group(1))
            # Adequate if at least 18 weeks (10886400 seconds)
            if max_age_val >= 10886400:
                max_age_adequate = 1.0
    evidence["hsts_max_age_adequate"] = max_age_adequate

    # 2. Content-Security-Policy
    csp = norm_headers.get("content-security-policy", "")
    has_csp = 1.0 if csp else 0.0
    evidence["has_csp"] = has_csp

    parsed_csp = parse_csp_directives(csp)
    evidence["csp_directive_count"] = float(len(parsed_csp))

    # Form-action directive restricted in CSP
    if "form-action" in parsed_csp:
        tokens = parsed_csp["form-action"]
        # Restricting form-action to 'self' or explicit trusted domains
        if "'none'" in tokens or "'self'" in tokens:
            evidence["csp_restricts_form_action"] = 1.0
        else:
            evidence["csp_restricts_form_action"] = 0.5
    else:
        evidence["csp_restricts_form_action"] = 0.0

    # Inline/eval restriction in script-src
    script_src = parsed_csp.get("script-src", parsed_csp.get("default-src", []))
    if has_csp:
        has_unsafe = any(t in ["'unsafe-inline'", "'unsafe-eval'"] for t in script_src)
        evidence["csp_blocks_eval_inline"] = 0.0 if has_unsafe else 1.0
    else:
        evidence["csp_blocks_eval_inline"] = 0.0

    # 3. X-Frame-Options
    xfo = norm_headers.get("x-frame-options", "").upper().strip()
    evidence["has_x_frame_options"] = 1.0 if xfo else 0.0
    evidence["x_frame_options_strict"] = 1.0 if xfo in ["DENY", "SAMEORIGIN"] else 0.0

    # 4. X-Content-Type-Options
    xcto = norm_headers.get("x-content-type-options", "").lower().strip()
    evidence["has_x_content_type_options"] = 1.0 if "nosniff" in xcto else 0.0

    # 5. Referrer-Policy
    ref = norm_headers.get("referrer-policy", "").strip()
    evidence["has_referrer_policy"] = 1.0 if ref else 0.0

    # 6. Permissions-Policy / Feature-Policy
    perm = norm_headers.get("permissions-policy", norm_headers.get("feature-policy", "")).strip()
    evidence["has_permissions_policy"] = 1.0 if perm else 0.0

    # 7. Cookie security flags
    # We can inspect Set-Cookie headers or passed cookie metadata
    cookie_headers = [v for k, v in norm_headers.items() if k == "set-cookie"]
    if cookies is not None and len(cookies) > 0:
        total_c = len(cookies)
        sec_c = sum(1 for c in cookies if c.get("secure", False))
        http_c = sum(1 for c in cookies if c.get("httponly", False))
        same_c = sum(1 for c in cookies if str(c.get("samesite", "")).lower() in ["lax", "strict"])
        evidence["cookie_secure_ratio"] = float(sec_c / total_c)
        evidence["cookie_httponly_ratio"] = float(http_c / total_c)
        evidence["cookie_samesite_ratio"] = float(same_c / total_c)
    elif cookie_headers:
        total_c = len(cookie_headers)
        sec_c = sum(1 for ch in cookie_headers if "secure" in ch.lower())
        http_c = sum(1 for ch in cookie_headers if "httponly" in ch.lower())
        same_c = sum(1 for ch in cookie_headers if "samesite" in ch.lower())
        evidence["cookie_secure_ratio"] = float(sec_c / total_c)
        evidence["cookie_httponly_ratio"] = float(http_c / total_c)
        evidence["cookie_samesite_ratio"] = float(same_c / total_c)
    else:
        # No cookies set (or neutral)
        evidence["cookie_secure_ratio"] = 1.0
        evidence["cookie_httponly_ratio"] = 1.0
        evidence["cookie_samesite_ratio"] = 1.0

    return evidence


def extract_tls_evidence(
    cert_dict: Optional[Dict[str, Any]] = None,
    cert_valid: bool = True,
    longevity_days: float = 365.0,
    issuer_name: str = ""
) -> Dict[str, float]:
    """
    Extracts TLS certificate security posture features.
    """
    evidence: Dict[str, float] = {}
    evidence["cert_valid"] = 1.0 if cert_valid else 0.0
    evidence["cert_longevity_days"] = float(max(0.0, longevity_days))

    # Free or short-lived automated cert indicator
    is_short_or_free = False
    issuer_lower = issuer_name.lower()
    if any(ca in issuer_lower for ca in FREE_SHORT_LIVED_CAS):
        is_short_or_free = True
    if longevity_days > 0 and longevity_days <= 90:
        is_short_or_free = True
    if not cert_valid:
        is_short_or_free = True

    evidence["cert_is_free_or_short_lived"] = 1.0 if is_short_or_free else 0.0
    return evidence


def extract_dom_behavior_evidence(
    html_content: str,
    base_url: str = "",
    redirect_history: Optional[List[str]] = None,
    reflection_probe: str = "<script>1</script>"
) -> Dict[str, float]:
    """
    Extracts behavioral signals from the rendered DOM and interaction checks.
    """
    evidence: Dict[str, float] = {}

    # Redirect chain tracking
    if redirect_history:
        chain_len = len(redirect_history)
        evidence["redirect_chain_length"] = float(chain_len)
        # Check domain switch across hops
        domains = []
        for u in redirect_history:
            ext = EXTRACTOR(u)
            d = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
            domains.append(d)
        unique_domains = set(domains)
        evidence["redirect_domain_switch"] = 1.0 if len(unique_domains) > 1 else 0.0
    else:
        evidence["redirect_chain_length"] = 0.0
        evidence["redirect_domain_switch"] = 0.0

    base_domain = ""
    if base_url:
        ext = EXTRACTOR(base_url)
        base_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()

    soup = BeautifulSoup(html_content, "html.parser") if html_content else None

    # Form action behavior
    cross_domain_form = 0.0
    insecure_http_form = 0.0

    if soup:
        forms = soup.find_all("form")
        for form in forms:
            action = (form.get("action") or "").strip()
            if action.lower().startswith("http://"):
                insecure_http_form = 1.0
            if action.startswith("http://") or action.startswith("https://"):
                a_ext = EXTRACTOR(action)
                a_domain = f"{a_ext.domain}.{a_ext.suffix}".lower() if a_ext.suffix else a_ext.domain.lower()
                if base_domain and a_domain and (a_domain != base_domain):
                    cross_domain_form = 1.0

    evidence["form_action_cross_domain"] = cross_domain_form
    evidence["form_action_insecure_http"] = insecure_http_form

    # Script reflection check: Does the page reflect unsanitized injection probes?
    # Simulates the Harmless XSS probe check mentioned in user proposal (<script>1</script> or alert probes)
    reflection_detected = 0.0
    if html_content and reflection_probe:
        if reflection_probe in html_content:
            reflection_detected = 1.0
    evidence["script_reflection_detected"] = reflection_detected

    # Anti-analysis UI behavior: disabling right-click / context menu
    has_rc_disabled = 0.0
    if html_content:
        lower_html = html_content.lower()
        if "oncontextmenu=\"return false\"" in lower_html or "event.button==2" in lower_html or "preventdefault()" in lower_html and "contextmenu" in lower_html:
            has_rc_disabled = 1.0
    evidence["has_right_click_disabled"] = has_rc_disabled

    return evidence


def extract_all_dynamic_evidence(
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[List[Dict[str, Any]]] = None,
    tls_info: Optional[Dict[str, Any]] = None,
    html_content: str = "",
    base_url: str = "",
    redirect_history: Optional[List[str]] = None,
    reflection_probe: str = ""
) -> Dict[str, float]:
    """
    Combines all dynamic browser-level evidence into the full dynamic feature vector.
    """
    res: Dict[str, float] = {col: 0.0 for col in DYNAMIC_BROWSER_FEATURES}

    # Header evidence
    h_evidence = extract_header_evidence(headers or {}, cookies)
    res.update(h_evidence)

    # TLS evidence
    tls_dict = tls_info or {}
    t_evidence = extract_tls_evidence(
        cert_valid=tls_dict.get("cert_valid", True),
        longevity_days=tls_dict.get("longevity_days", 365.0),
        issuer_name=tls_dict.get("issuer_name", "")
    )
    res.update(t_evidence)

    # DOM / Form / Reflection evidence
    b_evidence = extract_dom_behavior_evidence(
        html_content=html_content,
        base_url=base_url,
        redirect_history=redirect_history,
        reflection_probe=reflection_probe
    )
    res.update(b_evidence)

    # Ensure all defined columns are present
    for col in DYNAMIC_BROWSER_FEATURES:
        if col not in res:
            res[col] = 0.0

    return res
