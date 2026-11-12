"""
Static Feature Extraction for URLs and Page Content.
Extracts lexical, structural, and HTML content features.
"""

import math
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import tldextract

EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)

from beap.config import (
    HIGH_RISK_TLDS,
    PHISHING_KEYWORDS,
    SENSITIVE_FIELD_NAMES,
    STATIC_URL_FEATURES,
    STATIC_HTML_FEATURES
)

# Regex patterns
IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]+$")


def compute_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return float(entropy)


def extract_url_features(url: str) -> Dict[str, float]:
    """
    Extracts lexical and structural features from a URL string.
    """
    feats = {col: 0.0 for col in STATIC_URL_FEATURES}
    if not url:
        return feats

    url_str = url.strip()
    if not (url_str.startswith("http://") or url_str.startswith("https://")):
        url_for_parsing = "http://" + url_str
    else:
        url_for_parsing = url_str

    try:
        parsed = urlparse(url_for_parsing)
    except Exception:
        return feats

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    ext = EXTRACTOR(url_for_parsing)
    subdomains = ext.subdomain.split(".") if ext.subdomain else []

    feats["url_length"] = float(len(url_str))
    feats["hostname_length"] = float(len(hostname))
    feats["path_length"] = float(len(path))
    feats["num_dots"] = float(url_str.count("."))
    feats["num_hyphens"] = float(url_str.count("-"))
    feats["num_at_symbols"] = float(url_str.count("@"))
    feats["num_percent"] = float(url_str.count("%"))

    try:
        query_dict = parse_qs(query)
        feats["num_query_params"] = float(len(query_dict))
    except Exception:
        feats["num_query_params"] = 0.0

    # IP address check
    is_ip = 1.0 if (IPV4_PATTERN.match(hostname) or (IPV6_PATTERN.match(hostname) and ":" in hostname)) else 0.0
    feats["has_ip_address"] = is_ip

    feats["entropy"] = compute_entropy(url_str)
    feats["subdomain_count"] = float(len(subdomains))

    # TLD check
    tld_lower = (ext.suffix or "").lower()
    feats["is_high_risk_tld"] = 1.0 if tld_lower in HIGH_RISK_TLDS else 0.0

    # Suspicious keywords
    url_lower = url_str.lower()
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
    feats["suspicious_keyword_count"] = float(keyword_count)

    # Scheme
    feats["uses_https"] = 1.0 if parsed.scheme.lower() == "https" else 0.0

    # Double slash in path redirect
    feats["has_double_slash_redirect"] = 1.0 if "//" in path else 0.0

    # Digits in host
    digits_in_host = sum(1 for c in hostname if c.isdigit())
    feats["num_digits_in_host"] = float(digits_in_host)
    feats["ratio_digits_in_host"] = float(digits_in_host / len(hostname)) if hostname else 0.0

    return feats


def extract_html_features(html_content: str, base_url: str = "") -> Dict[str, float]:
    """
    Extracts structural and content features from HTML markup.
    """
    feats = {col: 0.0 for col in STATIC_HTML_FEATURES}
    if not html_content:
        return feats

    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception:
        return feats

    base_domain = ""
    if base_url:
        ext = EXTRACTOR(base_url)
        base_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()

    # Forms
    forms = soup.find_all("form")
    feats["num_forms"] = float(len(forms))

    empty_form_actions = 0
    external_form_actions = 0

    for form in forms:
        action = (form.get("action") or "").strip()
        if not action or action in ["#", "about:blank", "javascript:void(0);", "javascript:void(0)"]:
            empty_form_actions += 1
        elif action.startswith("http://") or action.startswith("https://"):
            action_ext = EXTRACTOR(action)
            action_domain = f"{action_ext.domain}.{action_ext.suffix}".lower() if action_ext.suffix else action_ext.domain.lower()
            if base_domain and action_domain and (action_domain != base_domain):
                external_form_actions += 1

    if forms:
        feats["empty_form_action_ratio"] = float(empty_form_actions / len(forms))
        feats["external_form_action_ratio"] = float(external_form_actions / len(forms))

    # Input fields
    inputs = soup.find_all("input")
    has_pwd = False
    has_sensitive = False
    has_hidden = False

    for inp in inputs:
        inp_type = (inp.get("type") or "text").lower()
        inp_name = (inp.get("name") or "").lower()
        inp_id = (inp.get("id") or "").lower()

        if inp_type == "password":
            has_pwd = True
        if inp_type == "hidden":
            has_hidden = True

        combined_desc = f"{inp_name} {inp_id}"
        if any(sf in combined_desc for sf in SENSITIVE_FIELD_NAMES):
            has_sensitive = True

    feats["has_password_input"] = 1.0 if has_pwd else 0.0
    feats["has_sensitive_input"] = 1.0 if has_sensitive else 0.0
    feats["has_hidden_inputs"] = 1.0 if has_hidden else 0.0

    # External scripts ratio
    scripts = soup.find_all("script", src=True)
    if scripts:
        ext_scripts = 0
        for s in scripts:
            src = s["src"].strip()
            if src.startswith("http://") or src.startswith("https://"):
                s_ext = EXTRACTOR(src)
                s_domain = f"{s_ext.domain}.{s_ext.suffix}".lower() if s_ext.suffix else s_ext.domain.lower()
                if base_domain and s_domain and (s_domain != base_domain):
                    ext_scripts += 1
        feats["external_script_ratio"] = float(ext_scripts / len(scripts))

    # External links ratio
    anchors = soup.find_all("a", href=True)
    if anchors:
        ext_anchors = 0
        for a in anchors:
            href = a["href"].strip()
            if href.startswith("http://") or href.startswith("https://"):
                a_ext = EXTRACTOR(href)
                a_domain = f"{a_ext.domain}.{a_ext.suffix}".lower() if a_ext.suffix else a_ext.domain.lower()
                if base_domain and a_domain and (a_domain != base_domain):
                    ext_anchors += 1
        feats["external_hyperlink_ratio"] = float(ext_anchors / len(anchors))

    # Media resources (images, links)
    media = soup.find_all(["img", "video", "source"], src=True)
    if media:
        ext_media = 0
        for m in media:
            src = m["src"].strip()
            if src.startswith("http://") or src.startswith("https://"):
                m_ext = EXTRACTOR(src)
                m_domain = f"{m_ext.domain}.{m_ext.suffix}".lower() if m_ext.suffix else m_ext.domain.lower()
                if base_domain and m_domain and (m_domain != base_domain):
                    ext_media += 1
        feats["external_media_ratio"] = float(ext_media / len(media))

    # Iframe
    iframes = soup.find_all("iframe")
    feats["has_iframe"] = 1.0 if len(iframes) > 0 else 0.0

    # Title mismatch: Check if page title contains a well-known brand that is not in the base_domain
    title_tag = soup.find("title")
    title_text = (title_tag.get_text() or "").lower() if title_tag else ""
    mismatch = False
    for brand in ["paypal", "apple", "microsoft", "google", "netflix", "chase", "amazon", "bank of america"]:
        if brand in title_text:
            if base_domain and (brand.replace(" ", "") not in base_domain.replace("-", "").replace(".", "")):
                mismatch = True
                break
    feats["title_brand_mismatch"] = 1.0 if mismatch else 0.0

    return feats


def extract_all_static_features(url: str, html_content: str = "") -> Dict[str, float]:
    """Combines URL and HTML features into a single static feature dictionary."""
    url_feats = extract_url_features(url)
    html_feats = extract_html_features(html_content, base_url=url)
    res = {}
    res.update(url_feats)
    res.update(html_feats)
    return res
