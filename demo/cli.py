"""
Command-Line Interface (CLI) for BEAP Phishing Detection.
Usage:
  python -m demo.cli --url "https://login-verification-paypal.xyz/auth"
  python -m demo.cli --url "https://portal.chase.com/login" --tau-low 0.30 --tau-high 0.70
"""

import os
import sys
import argparse
import json
import pandas as pd

from beap.config import DEFAULT_TAU_LOW, DEFAULT_TAU_HIGH
from beap.detector import BEAPDetector
from beap.crawler import BrowserProbe


def render_ascii_card(report):
    """Renders a formatted ASCII audit card for terminal display."""
    width = 72
    print("\n" + "=" * width)
    print(f" BEAP PHISHING DETECTION & EVIDENCE REPORT ".center(width, "="))
    print("=" * width)
    print(f" Target URL : {report.url}")
    print(f" Phish Score: {report.phishing_probability:.1%} ({report.phishing_probability:.4f})")

    # Status formatting
    if report.verdict == "PHISHING":
        badge = "[PHISHING]"
    elif report.verdict == "LEGITIMATE":
        badge = "[LEGITIMATE]"
    else:
        badge = "[UNCERTAIN - ABSTAINED]"

    print(f" Verdict    : {badge}")
    if report.abstained:
        print(f" Rationale  : {report.abstention_reason}")
    print(f" Action     : {report.action_recommendation}")
    print("-" * width)

    print(" TOP RISK SIGNALS (Phishing indicators):")
    if report.top_risk_signals:
        for s in report.top_risk_signals:
            print(f"   [-] {s.feature_name:<28} | Weight: {s.attribution_weight:+.3f}")
            print(f"       -> {s.explanation}")
    else:
        print("   (No significant risk signals detected)")

    print("-" * width)
    print(" TOP TRUST SIGNALS (Legitimate indicators):")
    if report.top_trust_signals:
        for s in report.top_trust_signals:
            print(f"   [+] {s.feature_name:<28} | Weight: {s.attribution_weight:+.3f}")
            print(f"       -> {s.explanation}")
    else:
        print("   (No significant trust signals detected)")

    print("=" * width + "\n")


def main():
    parser = argparse.ArgumentParser(description="BEAP Explainable Phishing Detector CLI")
    parser.add_argument("--url", type=str, help="Target URL to inspect")
    parser.add_argument("--tau-low", type=float, default=DEFAULT_TAU_LOW, help="Lower uncertainty threshold")
    parser.add_argument("--tau-high", type=float, default=DEFAULT_TAU_HIGH, help="Upper uncertainty threshold")
    parser.add_argument("--live", action="store_true", help="Perform live HTTP and TLS browser probe")
    parser.add_argument("--json", action="store_true", help="Output raw JSON report")

    args = parser.parse_args()

    # Load trained model
    train_path = os.path.join("data", "processed", "train.csv")
    if not os.path.exists(train_path):
        print("Dataset not found. Generating benchmark...")
        from data.generate_benchmark import main as gen_main
        gen_main()

    train_df = pd.read_csv(train_path)
    detector = BEAPDetector(
        feature_mode="multimodal_full",
        tau_low=args.tau_low,
        tau_high=args.tau_high,
        use_memory=True
    )
    detector.fit(train_df, train_df["label"].values.astype(int))

    target_url = args.url or "https://login-verification-paypal.xyz/account/auth"
    print(f"Analyzing: {target_url} (live_probe={args.live})...")

    pred, rep = detector.inspect_url(url=target_url, live_probe=args.live)

    if args.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        render_ascii_card(rep)


if __name__ == "__main__":
    main()

