"""
End-to-end BEAP Detector Pipeline.
Orchestrates static parsing, dynamic browser evidence collection,
explainable classification, selective abstention, and domain memory.
"""

from typing import Dict, Any, List, Optional, Tuple, Union
import numpy as np

from beap.config import (
    DEFAULT_TAU_LOW,
    DEFAULT_TAU_HIGH,
    STATIC_URL_FEATURES,
    STATIC_HTML_FEATURES,
    DYNAMIC_BROWSER_FEATURES,
    ALL_FEATURE_COLUMNS
)
from beap.feature_pipeline import BEAPFeaturePipeline
from beap.models import BEAPLogisticRegression, BEAPXGBoost, ExplainableClassifier
from beap.abstention import AbstentionEngine, SelectivePrediction, DecisionVerdict
from beap.explainer import BEAPExplainer, ExplanationReport
from beap.domain_memory import DomainMemoryCache
from beap.crawler import BrowserProbe, PageProbeResult


class BEAPDetector:
    """
    Main BEAP System.
    Combines static and dynamic browser evidence with explainable classification
    and uncertainty-driven selective abstention.
    """

    def __init__(
        self,
        classifier: Optional[ExplainableClassifier] = None,
        feature_mode: str = "multimodal_full",
        tau_low: float = DEFAULT_TAU_LOW,
        tau_high: float = DEFAULT_TAU_HIGH,
        use_memory: bool = True
    ):
        self.feature_mode = feature_mode
        self.pipeline = BEAPFeaturePipeline(feature_mode=feature_mode)
        self.classifier = classifier or BEAPLogisticRegression()
        self.abstention_engine = AbstentionEngine(tau_low=tau_low, tau_high=tau_high)
        self.explainer = BEAPExplainer(top_k=5)
        self.use_memory = use_memory
        self.memory = DomainMemoryCache() if use_memory else None
        self.probe = BrowserProbe()

    def fit(self, X_data: Any, y: np.ndarray):
        """Fits feature pipeline and classifier."""
        X_vecs = self.pipeline.fit_transform(X_data)
        self.classifier.fit(X_vecs, y)
        return self

    def analyze_features(
        self,
        url: str,
        feature_dict: Dict[str, float],
        timestamp: Optional[float] = None
    ) -> Tuple[SelectivePrediction, ExplanationReport]:
        """
        Analyzes a pre-extracted feature dictionary.
        """
        # Vectorize
        X_vec = self.pipeline.transform(feature_dict)

        # Predict base probability
        base_prob = float(self.classifier.predict_proba(X_vec)[0])

        # Apply domain memory bias if enabled
        adjusted_prob = base_prob
        if self.use_memory and self.memory:
            bias, weight, past_verdict = self.memory.lookup(url, current_time=timestamp)
            if weight > 0.05:
                # Soft Bayesian-like prior shift: adjust log-odds or probability smoothly
                adjusted_prob = float(np.clip(base_prob + 0.15 * bias, 0.001, 0.999))

        # Check subscores for epistemic conflict if multimodal
        static_subscore = None
        dynamic_subscore = None
        if self.feature_mode == "multimodal_full":
            # Estimate static and dynamic balance
            static_cols = [c for c in self.pipeline.columns if c in (STATIC_URL_FEATURES + STATIC_HTML_FEATURES)]
            dynamic_cols = [c for c in self.pipeline.columns if c in DYNAMIC_BROWSER_FEATURES]

            # Approximate sub-scores via local attributions or feature means
            pass

        # Apply selective decision rule
        selective_pred = self.abstention_engine.classify_sample(
            prob=adjusted_prob,
            static_subscore=static_subscore,
            dynamic_subscore=dynamic_subscore
        )

        # Compute local feature attributions and baseline
        explain_res = self.classifier.explain_instance(X_vec, self.pipeline.columns)
        attributions = explain_res.get("attributions", {})
        baseline_log_odds = explain_res.get("baseline_log_odds", 0.0)
        total_predicted_log_odds = explain_res.get("total_predicted_log_odds", 0.0)

        # Generate human-readable report
        report = self.explainer.generate_report(
            url=url,
            verdict=selective_pred.verdict,
            prob=selective_pred.phishing_probability,
            abstained=selective_pred.abstained,
            abstention_reason=selective_pred.abstention_reason,
            attributions=attributions,
            raw_features=feature_dict,
            baseline_log_odds=baseline_log_odds,
            total_predicted_log_odds=total_predicted_log_odds
        )

        # Record in memory if definitive
        if self.use_memory and self.memory and not selective_pred.abstained:
            self.memory.record(url, selective_pred.verdict, selective_pred.phishing_probability, timestamp=timestamp)

        return selective_pred, report

    def inspect_url(
        self,
        url: str,
        html_content: str = "",
        headers: Optional[Dict[str, str]] = None,
        tls_info: Optional[Dict[str, Any]] = None,
        cookies: Optional[List[Dict[str, Any]]] = None,
        live_probe: bool = False
    ) -> Tuple[SelectivePrediction, ExplanationReport]:
        """
        Inspects a URL either using provided metadata or by initiating a live browser probe.
        """
        if live_probe:
            probe_res = self.probe.probe_url(url)
            html_content = probe_res.html_content
            headers = probe_res.headers
            tls_info = probe_res.tls_info
            cookies = probe_res.cookies

        raw_feats = self.pipeline.extract_raw_features(
            url=url,
            html_content=html_content,
            headers=headers,
            cookies=cookies,
            tls_info=tls_info
        )

        return self.analyze_features(url, raw_feats)

