"""
Domain Memory and Cache Module.
Provides recency-weighted domain history lookup to adaptively
incorporate recent campaign observations into detection context.
"""

import math
import time
from typing import Dict, Any, Optional, Tuple
import tldextract

EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


class DomainMemoryCache:
    """
    In-memory and JSON-serializable cache of previously observed domains.
    Weights domain reputation using an exponential decay half-life.
    """

    def __init__(self, half_life_hours: float = 24.0, max_entries: int = 5000):
        self.half_life_hours = half_life_hours
        self.decay_rate = math.log(2.0) / (half_life_hours * 3600.0)  # lambda per second
        self.max_entries = max_entries
        # Mapping: domain -> {"verdict": str, "prob": float, "timestamp": float, "count": int}
        self.cache: Dict[str, Dict[str, Any]] = {}

    def _get_registrable_domain(self, url_or_host: str) -> str:
        """Extracts registrable domain (e.g., example.com from sub.example.com)."""
        ext = EXTRACTOR(url_or_host)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return ext.domain.lower() if ext.domain else url_or_host.lower()

    def record(self, url: str, verdict: str, prob: float, timestamp: Optional[float] = None):
        """Records an observed URL decision into the memory cache."""
        domain = self._get_registrable_domain(url)
        if not domain:
            return

        ts = timestamp if timestamp is not None else time.time()

        if domain in self.cache:
            entry = self.cache[domain]
            entry["verdict"] = verdict
            entry["prob"] = (entry["prob"] * entry["count"] + prob) / (entry["count"] + 1)
            entry["count"] += 1
            entry["timestamp"] = ts
        else:
            if len(self.cache) >= self.max_entries:
                # Evict oldest entry
                oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]["timestamp"])
                del self.cache[oldest_key]

            self.cache[domain] = {
                "verdict": verdict,
                "prob": float(prob),
                "timestamp": ts,
                "count": 1
            }

    def lookup(self, url: str, current_time: Optional[float] = None) -> Tuple[float, float, str]:
        """
        Looks up domain in memory cache.
        Returns:
            (reputation_bias, weight, past_verdict)
            where weight in [0, 1] indicates recency confidence,
            reputation_bias is in [-1.0 (benign), +1.0 (phishing)].
        """
        domain = self._get_registrable_domain(url)
        if domain not in self.cache:
            return 0.0, 0.0, "UNKNOWN"

        entry = self.cache[domain]
        now = current_time if current_time is not None else time.time()
        elapsed_seconds = max(0.0, now - entry["timestamp"])

        # Exponential decay: w = exp(-lambda * t)
        recency_weight = math.exp(-self.decay_rate * elapsed_seconds)

        # Reputation bias centered around 0.5: prob in [0, 1] -> bias in [-1, +1]
        bias = 2.0 * (entry["prob"] - 0.5)

        return float(bias * recency_weight), float(recency_weight), entry["verdict"]

    def clear(self):
        self.cache.clear()
