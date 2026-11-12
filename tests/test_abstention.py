"""
Unit tests for the Selective Abstention Engine.
"""

import numpy as np
import pytest
from beap.abstention import AbstentionEngine, DecisionVerdict


def test_dual_threshold_classification():
    engine = AbstentionEngine(tau_low=0.35, tau_high=0.65)

    # Definite legitimate
    pred_legit = engine.classify_sample(prob=0.15)
    assert pred_legit.verdict == DecisionVerdict.LEGITIMATE
    assert pred_legit.abstained is False

    # Definite phishing
    pred_phish = engine.classify_sample(prob=0.88)
    assert pred_phish.verdict == DecisionVerdict.PHISHING
    assert pred_phish.abstained is False

    # Uncertain / Abstain
    pred_uncertain = engine.classify_sample(prob=0.52)
    assert pred_uncertain.verdict == DecisionVerdict.UNCERTAIN
    assert pred_uncertain.abstained is True
    assert "Inconclusive Evidence" in pred_uncertain.abstention_reason


def test_conflicting_evidence_abstention():
    engine = AbstentionEngine(tau_low=0.35, tau_high=0.65, conflict_threshold=0.40)
    # Static says 0.80 (phish), dynamic says 0.20 (legit), combined probability is ~0.50
    pred = engine.classify_sample(prob=0.50, static_subscore=0.80, dynamic_subscore=0.20)
    assert pred.verdict == DecisionVerdict.UNCERTAIN
    assert pred.abstained is True
    assert "Conflicting Evidence" in pred.abstention_reason


def test_coverage_risk_curve_calculation():
    engine = AbstentionEngine()
    y_true = np.array([0, 0, 0, 1, 1, 1])
    y_prob = np.array([0.05, 0.10, 0.45, 0.55, 0.90, 0.95])

    res = engine.evaluate_coverage_risk_curve(y_true, y_prob, num_thresholds=10)
    assert "coverages" in res
    assert "selective_risks" in res
    assert "aurc" in res
    assert len(res["coverages"]) == 10
    # At delta = 0, coverage must be 1.0
    assert pytest.approx(res["coverages"][0], 0.01) == 1.0

