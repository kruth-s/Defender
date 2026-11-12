"""
BEAP: Explainable Phishing Detection with Browser-based Evidence and Selective Abstention.
"""

from beap.config import (
    DEFAULT_TAU_LOW,
    DEFAULT_TAU_HIGH,
    STATIC_URL_FEATURES,
    STATIC_HTML_FEATURES,
    DYNAMIC_BROWSER_FEATURES,
    ALL_FEATURE_COLUMNS,
)
from beap.detector import BEAPDetector
from beap.abstention import AbstentionEngine, DecisionVerdict, SelectivePrediction
from beap.explainer import BEAPExplainer, ExplanationReport
from beap.models import BEAPLogisticRegression, BEAPXGBoost, BEAPDecisionTree
from beap.feature_pipeline import BEAPFeaturePipeline

__version__ = "1.0.0"

__all__ = [
    "BEAPDetector",
    "AbstentionEngine",
    "DecisionVerdict",
    "SelectivePrediction",
    "BEAPExplainer",
    "ExplanationReport",
    "BEAPLogisticRegression",
    "BEAPXGBoost",
    "BEAPDecisionTree",
    "BEAPFeaturePipeline",
    "DEFAULT_TAU_LOW",
    "DEFAULT_TAU_HIGH",
    "ALL_FEATURE_COLUMNS",
]

