"""
Explainable Lightweight Classifiers for BEAP.
Supports Logistic Regression with exact log-odds baseline decomposition and
XGBoost with native TreeSHAP attributions.
"""

from typing import Dict, Any, List, Optional, Tuple, Union
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
import xgboost as xgb


class ExplainableClassifier:
    """Base class for explainable phishing classifiers."""

    def fit(self, X: np.ndarray, y: np.ndarray):
        raise NotImplementedError

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        raise NotImplementedError

    def predict(self, X: np.ndarray) -> np.ndarray:
        raise NotImplementedError

    def get_global_importances(self, feature_names: List[str]) -> Dict[str, float]:
        raise NotImplementedError

    def explain_instance(self, x: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        raise NotImplementedError


class BEAPLogisticRegression(ExplainableClassifier):
    """
    L2-regularized Logistic Regression with mathematically complete log-odds decomposition:
    logit(p) = w_0 + sum(w_i * x_i) = baseline_log_odds + sum(phi_i)
    where:
      baseline_log_odds = w_0 + sum(w_i * mean_i)
      phi_i = w_i * (x_i - mean_i)
    This guarantees: baseline_log_odds + sum(phi_i) == logit(p).
    """

    def __init__(self, C: float = 1.0, max_iter: int = 1000, random_state: int = 42):
        self.model = LogisticRegression(C=C, max_iter=max_iter, random_state=random_state)
        self.feature_names: List[str] = []
        self.mean_vector: Optional[np.ndarray] = None
        self.baseline_log_odds: float = 0.0

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        self.mean_vector = np.mean(X, axis=0)
        coefs = self.model.coef_[0]
        intercept = float(self.model.intercept_[0])
        self.baseline_log_odds = float(intercept + np.dot(coefs, self.mean_vector))
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict_proba(X)[:, 1]

    def predict(self, X: np.ndarray) -> np.ndarray:
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict(X)

    def get_global_importances(self, feature_names: List[str]) -> Dict[str, float]:
        coefs = self.model.coef_[0]
        imp = {name: float(coefs[i]) for i, name in enumerate(feature_names)}
        return dict(sorted(imp.items(), key=lambda item: abs(item[1]), reverse=True))

    def explain_instance(self, x: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        """
        Returns full additive decomposition including:
        - 'baseline_log_odds': expected log-odds at dataset mean
        - 'intercept': raw model bias w_0
        - 'attributions': per-feature contributions phi_i = w_i * (x_i - mean_i)
        - 'total_predicted_log_odds': baseline_log_odds + sum(phi_i)
        - 'reconstructed_probability': sigma(total_predicted_log_odds)
        """
        if x.ndim > 1:
            x_vec = x.flatten()
        else:
            x_vec = x

        coefs = self.model.coef_[0]
        intercept = float(self.model.intercept_[0])
        base_mean = self.mean_vector if self.mean_vector is not None else np.zeros_like(x_vec)

        attributions = {}
        for i, name in enumerate(feature_names):
            diff = x_vec[i] - base_mean[i]
            contrib = float(coefs[i] * diff)
            attributions[name] = contrib

        total_log_odds = float(self.baseline_log_odds + sum(attributions.values()))
        prob = 1.0 / (1.0 + np.exp(-total_log_odds))

        sorted_attributions = dict(sorted(attributions.items(), key=lambda item: abs(item[1]), reverse=True))

        return {
            "baseline_log_odds": self.baseline_log_odds,
            "intercept": intercept,
            "attributions": sorted_attributions,
            "total_predicted_log_odds": total_log_odds,
            "reconstructed_probability": prob
        }


class BEAPXGBoost(ExplainableClassifier):
    """
    Gradient Boosted Decision Trees with native TreeSHAP attribution:
    f(x) = base_value + sum(phi_i)
    """

    def __init__(
        self,
        n_estimators: int = 80,
        max_depth: int = 4,
        learning_rate: float = 0.1,
        random_state: int = 42
    ):
        self.model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            random_state=random_state,
            eval_metric="logloss"
        )
        self.feature_names: List[str] = []

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict_proba(X)[:, 1]

    def predict(self, X: np.ndarray) -> np.ndarray:
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict(X)

    def get_global_importances(self, feature_names: List[str]) -> Dict[str, float]:
        importances = self.model.feature_importances_
        imp = {name: float(importances[i]) for i, name in enumerate(feature_names)}
        return dict(sorted(imp.items(), key=lambda item: item[1], reverse=True))

    def explain_instance(self, x: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        """Computes exact TreeSHAP values including base value."""
        if x.ndim == 1:
            x_mat = x.reshape(1, -1)
        else:
            x_mat = x

        dmat = xgb.DMatrix(x_mat)
        contribs = self.model.get_booster().predict(dmat, pred_contribs=True)[0]
        feature_contribs = contribs[:-1]
        base_value = float(contribs[-1])

        attributions = {name: float(feature_contribs[i]) for i, name in enumerate(feature_names)}
        sorted_attributions = dict(sorted(attributions.items(), key=lambda item: abs(item[1]), reverse=True))
        total_margin = float(base_value + sum(feature_contribs))
        prob = 1.0 / (1.0 + np.exp(-total_margin))

        return {
            "baseline_log_odds": base_value,
            "intercept": base_value,
            "attributions": sorted_attributions,
            "total_predicted_log_odds": total_margin,
            "reconstructed_probability": prob
        }


class BEAPDecisionTree(ExplainableClassifier):
    """
    Shallow Decision Tree for interpretable path inspection.
    """

    def __init__(self, max_depth: int = 4, random_state: int = 42):
        self.model = DecisionTreeClassifier(max_depth=max_depth, random_state=random_state)
        self.feature_names: List[str] = []

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict_proba(X)[:, 1]

    def predict(self, X: np.ndarray) -> np.ndarray:
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict(X)

    def get_global_importances(self, feature_names: List[str]) -> Dict[str, float]:
        importances = self.model.feature_importances_
        imp = {name: float(importances[i]) for i, name in enumerate(feature_names)}
        return dict(sorted(imp.items(), key=lambda item: item[1], reverse=True))

    def explain_instance(self, x: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        if x.ndim == 1:
            x_mat = x.reshape(1, -1)
        else:
            x_mat = x

        node_indicator = self.model.decision_path(x_mat)
        node_indices = node_indicator.indices
        feature_indices = self.model.tree_.feature

        attributions = {name: 0.0 for name in feature_names}
        prob = float(self.predict_proba(x_mat)[0])
        direction = 1.0 if prob >= 0.5 else -1.0

        for node_id in node_indices:
            f_idx = feature_indices[node_id]
            if f_idx >= 0:
                name = feature_names[f_idx]
                attributions[name] += direction * (abs(prob - 0.5) / max(1, len(node_indices)))

        sorted_attributions = dict(sorted(attributions.items(), key=lambda item: abs(item[1]), reverse=True))
        return {
            "baseline_log_odds": 0.0,
            "intercept": 0.0,
            "attributions": sorted_attributions,
            "total_predicted_log_odds": float(np.log(prob / max(1e-5, 1.0 - prob))),
            "reconstructed_probability": prob
        }
