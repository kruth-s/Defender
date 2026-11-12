"""
Unified Feature Extraction and Pipeline Vectorizer.
"""

from typing import Dict, Any, List, Optional, Tuple, Union
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from beap.config import (
    STATIC_URL_FEATURES,
    STATIC_HTML_FEATURES,
    DYNAMIC_BROWSER_FEATURES,
    ALL_FEATURE_COLUMNS,
)
from beap.static_features import extract_all_static_features
from beap.browser_evidence import extract_all_dynamic_evidence


class BEAPFeaturePipeline:
    """
    Transforms raw webpage artifacts (URL, HTML, Headers, TLS, Behavior)
    into structured numeric feature vectors, with subset slicing and scaling.
    """

    def __init__(self, feature_mode: str = "multimodal_full", scale_features: bool = True):
        """
        feature_mode:
            - 'static_url': URL lexical features only
            - 'static_all': URL + HTML static features
            - 'dynamic_only': HTTP headers + TLS + Form behavior
            - 'multimodal_full': Full combination of static and dynamic evidence
        """
        self.feature_mode = feature_mode
        self.scale_features = scale_features
        self.scaler = StandardScaler()
        self.is_fitted = False

        if feature_mode == "static_url":
            self.columns = list(STATIC_URL_FEATURES)
        elif feature_mode == "static_all":
            self.columns = list(STATIC_URL_FEATURES + STATIC_HTML_FEATURES)
        elif feature_mode == "dynamic_only":
            self.columns = list(DYNAMIC_BROWSER_FEATURES)
        elif feature_mode == "multimodal_full":
            self.columns = list(ALL_FEATURE_COLUMNS)
        else:
            raise ValueError(f"Unknown feature mode: {feature_mode}")

    def extract_raw_features(
        self,
        url: str,
        html_content: str = "",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[List[Dict[str, Any]]] = None,
        tls_info: Optional[Dict[str, Any]] = None,
        redirect_history: Optional[List[str]] = None,
        reflection_probe: str = ""
    ) -> Dict[str, float]:
        """
        Extracts a dictionary of all static and dynamic features from raw inputs.
        """
        static_feats = extract_all_static_features(url, html_content)
        dynamic_feats = extract_all_dynamic_evidence(
            headers=headers,
            cookies=cookies,
            tls_info=tls_info,
            html_content=html_content,
            base_url=url,
            redirect_history=redirect_history,
            reflection_probe=reflection_probe
        )
        combined = {}
        combined.update(static_feats)
        combined.update(dynamic_feats)
        return combined

    def dict_to_vector(self, feature_dict: Dict[str, float]) -> np.ndarray:
        """Converts feature dictionary to vector aligned with self.columns."""
        vec = np.zeros((1, len(self.columns)), dtype=np.float32)
        for i, col in enumerate(self.columns):
            vec[0, i] = float(feature_dict.get(col, 0.0))
        return vec

    def dataframe_to_matrix(self, df: pd.DataFrame) -> np.ndarray:
        """Extracts self.columns from dataframe into numpy array."""
        for col in self.columns:
            if col not in df.columns:
                df[col] = 0.0
        subset_df = df[self.columns].copy()
        subset_df = subset_df.fillna(0.0)
        return subset_df.values.astype(np.float32)

    def fit(self, X: Union[pd.DataFrame, np.ndarray]):
        """Fits standard scaler if enabled."""
        if isinstance(X, pd.DataFrame):
            mat = self.dataframe_to_matrix(X)
        else:
            mat = X
        if self.scale_features:
            self.scaler.fit(mat)
        self.is_fitted = True
        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray, Dict[str, float]]) -> np.ndarray:
        """Transforms input into scaled feature matrix."""
        if isinstance(X, dict):
            mat = self.dict_to_vector(X)
        elif isinstance(X, pd.DataFrame):
            mat = self.dataframe_to_matrix(X)
        else:
            mat = X

        if self.scale_features and self.is_fitted:
            return self.scaler.transform(mat)
        return mat

    def fit_transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        return self.fit(X).transform(X)

