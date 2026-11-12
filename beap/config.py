"""
Configuration and constants for BEAP (Browser-driven Evidence Augmentation & Abstention Phish Detector).
"""

from typing import List, Dict, Any

# Security headers to inspect
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

# High-risk / suspicious TLDs frequently abused in ephemeral phishing campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "cf", "gq", "ga", "buzz", "rest", "cam", 
    "work", "icu", "site", "online", "surf", "fit", "sbs", "cfd", "monster"
}

# Suspicious keywords frequently observed in phishing URLs / forms
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "account", "update", "verify",
    "verification", "security", "secure", "authenticate", "auth", "banking",
    "wallet", "crypto", "confirm", "billing", "suspended", "service",
    "support", "recover", "ebay", "paypal", "apple", "microsoft", "google",
    "netflix", "chase", "wellsfargo", "bankofamerica", "citi", "amazon"
]

# Sensitive input field names (credential harvesting indicators)
SENSITIVE_FIELD_NAMES = [
    "password", "pass", "pwd", "secret", "cvv", "cvc", "creditcard",
    "card_number", "ssn", "social_security", "pin", "otp", "token",
    "identity", "routing", "dob"
]

# Abstention decision configuration
DEFAULT_TAU_LOW = 0.35
DEFAULT_TAU_HIGH = 0.65
DEFAULT_DELTA = 0.15

# Memory decay constant (half-life in hours for domain memory)
MEMORY_DECAY_HOURS = 24.0

# Feature group definitions for ablation studies
STATIC_URL_FEATURES = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_at_symbols",
    "num_percent",
    "num_query_params",
    "has_ip_address",
    "entropy",
    "subdomain_count",
    "is_high_risk_tld",
    "suspicious_keyword_count",
    "uses_https",
    "has_double_slash_redirect",
    "num_digits_in_host",
    "ratio_digits_in_host",
]

STATIC_HTML_FEATURES = [
    "num_forms",
    "has_password_input",
    "has_sensitive_input",
    "empty_form_action_ratio",
    "external_form_action_ratio",
    "external_script_ratio",
    "external_hyperlink_ratio",
    "external_media_ratio",
    "has_iframe",
    "has_hidden_inputs",
    "title_brand_mismatch",
]

DYNAMIC_BROWSER_FEATURES = [
    "has_hsts",
    "hsts_max_age_adequate",
    "has_csp",
    "csp_directive_count",
    "csp_restricts_form_action",
    "csp_blocks_eval_inline",
    "has_x_frame_options",
    "x_frame_options_strict",
    "has_x_content_type_options",
    "has_referrer_policy",
    "has_permissions_policy",
    "cookie_secure_ratio",
    "cookie_httponly_ratio",
    "cookie_samesite_ratio",
    "redirect_chain_length",
    "redirect_domain_switch",
    "cert_valid",
    "cert_longevity_days",
    "cert_is_free_or_short_lived",
    "form_action_cross_domain",
    "form_action_insecure_http",
    "script_reflection_detected",
    "has_right_click_disabled",
]

ALL_FEATURE_COLUMNS = STATIC_URL_FEATURES + STATIC_HTML_FEATURES + DYNAMIC_BROWSER_FEATURES

