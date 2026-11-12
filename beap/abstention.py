"""
Selective Abstention Engine for Phishing Detection.
Implements dual-threshold selective classification, uncertainty quantification,
coverage-risk trade-off analysis, and conflicting-evidence detection.
"""

from typing import Dict, Any, List, Optional, Tuple, NamedTuple
from dataclasses import dataclass
import numpy as np


class DecisionVerdict(str):
    LEGITIMATE = "LEGITIMATE"
    PHISHING = "PHISHING"
    UNCERTAIN = "UNCERTAIN_ABSTAIN"


@dataclass
class SelectivePrediction:
    verdict: str                  # LEGITIMATE, PHISHING, UNCERTAIN_ABSTAIN
    phishing_probability: float  # Posterior P(phishing|x) in [0, 1]
    confidence_margin: float     # |p - 0.5|
    abstained: bool              # True if verdict is UNCERTAIN_ABSTAIN
    abstention_reason: str       # Text explanation of why system abstained
    tau_low: float               # Lower threshold
    tau_high: float              # Upper threshold


class AbstentionEngine:
    """
    Manages selective classification thresholds, uncertainty scoring,
    and coverage-risk trade-off evaluation.
    """

    def __init__(
        self,
        tau_low: float = 0.35,
        tau_high: float = 0.65,
        conflict_threshold: float = 0.40
    ):
        """
        tau_low: Lower decision threshold. Scores <= tau_low are classified as LEGITIMATE.
        tau_high: Upper decision threshold. Scores >= tau_high are classified as PHISHING.
        conflict_threshold: Margin difference between static and dynamic sub-scores to flag epistemic conflict.
        """
        assert 0.0 <= tau_low < tau_high <= 1.0, "Thresholds must satisfy 0 <= tau_low < tau_high <= 1"
        self.tau_low = tau_low
        self.tau_high = tau_high
        self.conflict_threshold = conflict_threshold

    def classify_sample(
        self,
        prob: float,
        static_subscore: Optional[float] = None,
        dynamic_subscore: Optional[float] = None
    ) -> SelectivePrediction:
        """
        Applies dual-threshold selective decision rule and conflict detection.
        """
        margin = abs(prob - 0.5)
        abstained = False
        reason = ""

        # Check for conflicting evidence if both modalities are available
        if static_subscore is not None and dynamic_subscore is not None:
            discrepancy = abs(static_subscore - dynamic_subscore)
            if discrepancy >= self.conflict_threshold and (0.25 <= prob <= 0.75):
                return SelectivePrediction(
                    verdict=DecisionVerdict.UNCERTAIN,
                    phishing_probability=float(prob),
                    confidence_margin=float(margin),
                    abstained=True,
                    abstention_reason=(
                        f"Conflicting Evidence: Static model estimated p={static_subscore:.2f} "
                        f"while Browser Evidence estimated p={dynamic_subscore:.2f} "
                        f"(discrepancy={discrepancy:.2f} >= {self.conflict_threshold:.2f})."
                    ),
                    tau_low=self.tau_low,
                    tau_high=self.tau_high
                )

        # Standard dual-threshold margin check
        if prob >= self.tau_high:
            verdict = DecisionVerdict.PHISHING
            reason = f"High phishing confidence (p={prob:.3f} >= tau_high={self.tau_high:.2f})"
        elif prob <= self.tau_low:
            verdict = DecisionVerdict.LEGITIMATE
            reason = f"High legitimate confidence (p={prob:.3f} <= tau_low={self.tau_low:.2f})"
        else:
            verdict = DecisionVerdict.UNCERTAIN
            abstained = True
            reason = (
                f"Inconclusive Evidence: Score p={prob:.3f} lies in uncertainty window "
                f"({self.tau_low:.2f}, {self.tau_high:.2f}). Confidence margin={margin:.3f}."
            )

        return SelectivePrediction(
            verdict=verdict,
            phishing_probability=float(prob),
            confidence_margin=float(margin),
            abstained=abstained,
            abstention_reason=reason,
            tau_low=self.tau_low,
            tau_high=self.tau_high
        )

    def evaluate_coverage_risk_curve(
        self,
        y_true: np.ndarray,
        y_prob: np.ndarray,
        num_thresholds: int = 50
    ) -> Dict[str, Any]:
        """
        Sweeps symmetric margins delta in [0, 0.49] to compute the full
        Coverage-Risk (RC) profile and selective performance metrics.
        """
        deltas = np.linspace(0.0, 0.48, num_thresholds)
        coverages = []
        selective_risks = []
        selective_accuracies = []
        selective_fnrs = []
        selective_fprs = []
        abstention_rates = []

        total_samples = len(y_true)

        for delta in deltas:
            t_low = 0.5 - delta
            t_high = 0.5 + delta

            # Mask of accepted samples
            accepted_mask = (y_prob <= t_low) | (y_prob >= t_high)
            num_accepted = int(np.sum(accepted_mask))
            coverage = float(num_accepted / total_samples) if total_samples > 0 else 0.0
            abstention_rate = 1.0 - coverage

            if num_accepted == 0:
                # If no samples accepted, risk is undefined/0
                coverages.append(coverage)
                abstention_rates.append(abstention_rate)
                selective_risks.append(0.0)
                selective_accuracies.append(1.0)
                selective_fnrs.append(0.0)
                selective_fprs.append(0.0)
                continue

            y_true_acc = y_true[accepted_mask]
            y_prob_acc = y_prob[accepted_mask]
            y_pred_acc = (y_prob_acc >= 0.5).astype(int)

            # Error rate on accepted cases
            errors = np.sum(y_pred_acc != y_true_acc)
            risk = float(errors / num_accepted)
            acc = 1.0 - risk

            # FNR on accepted: true phish (y=1) predicted as leg (y=0)
            phish_mask = (y_true_acc == 1)
            num_phish = np.sum(phish_mask)
            fnr = float(np.sum((y_pred_acc == 0) & phish_mask) / num_phish) if num_phish > 0 else 0.0

            # FPR on accepted: true leg (y=0) predicted as phish (y=1)
            leg_mask = (y_true_acc == 0)
            num_leg = np.sum(leg_mask)
            fpr = float(np.sum((y_pred_acc == 1) & leg_mask) / num_leg) if num_leg > 0 else 0.0

            coverages.append(coverage)
            abstention_rates.append(abstention_rate)
            selective_risks.append(risk)
            selective_accuracies.append(acc)
            selective_fnrs.append(fnr)
            selective_fprs.append(fpr)

        # Compute Area Under Risk-Coverage Curve (AURC) via trapezoidal integration
        # Note: Coverages are decreasing as delta increases, so sort by coverage
        sorted_indices = np.argsort(coverages)
        cov_sorted = np.array(coverages)[sorted_indices]
        risk_sorted = np.array(selective_risks)[sorted_indices]
        trap_func = getattr(np, "trapezoid", getattr(np, "trapz", None))
        aurc = float(trap_func(risk_sorted, cov_sorted))

        return {
            "deltas": deltas.tolist(),
            "coverages": coverages,
            "abstention_rates": abstention_rates,
            "selective_risks": selective_risks,
            "selective_accuracies": selective_accuracies,
            "selective_fnrs": selective_fnrs,
            "selective_fprs": selective_fprs,
            "aurc": aurc
        }
