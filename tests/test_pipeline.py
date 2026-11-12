"""
Unit tests for end-to-end BEAP detector and domain memory.
"""

import time
import numpy as np
import pandas as pd
import pytest

from beap.detector import BEAPDetector
from beap.domain_memory import DomainMemoryCache


def test_domain_memory_cache():
    cache = DomainMemoryCache(half_life_hours=1.0)
    now = time.time()
    cache.record("https://phish-login.xyz/auth", verdict="PHISHING", prob=0.95, timestamp=now)

    # Immediately after record
    bias, weight, verdict = cache.lookup("https://phish-login.xyz/different_path", current_time=now)
    assert verdict == "PHISHING"
    assert weight > 0.99
    assert bias > 0.80

    # 1 hour later (half life)
    bias_half, weight_half, _ = cache.lookup("https://phish-login.xyz", current_time=now + 3600)
    assert pytest.approx(weight_half, 0.05) == 0.50

    # Unknown domain
    b_unk, w_unk, v_unk = cache.lookup("https://unseen-domain.com")
    assert w_unk == 0.0
    assert v_unk == "UNKNOWN"


def test_end_to_end_detector():
    train_df = pd.read_csv("data/processed/train.csv").head(100)
    detector = BEAPDetector(feature_mode="multimodal_full", tau_low=0.35, tau_high=0.65)
    detector.fit(train_df, train_df["label"].values.astype(int))

    url = "https://login-secure-auth.xyz/confirm"
    pred, rep = detector.inspect_url(
        url=url,
        headers={"Strict-Transport-Security": "max-age=31536000"},
        tls_info={"cert_valid": True, "longevity_days": 180.0, "issuer_name": "DigiCert"}
    )

    assert rep.url == url
    assert 0.0 <= rep.phishing_probability <= 1.0
    assert rep.verdict in ["LEGITIMATE", "PHISHING", "UNCERTAIN_ABSTAIN"]
    assert len(rep.top_risk_signals) <= 5
    assert len(rep.top_trust_signals) <= 5
    assert rep.action_recommendation != ""

