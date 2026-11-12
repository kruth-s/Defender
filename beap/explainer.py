"""
Explainability Module for BEAP.
Translates numeric feature attributions (SHAP / log-odds) into structured,
human-interpretable security audit diagnostics.
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass


# Human-friendly descriptions for feature triggers
FEATURE_EXPLANATIONS = {
    "form_action_cross_domain": {
        "risk": "CRITICAL: Web form submits submitted credentials to an external foreign domain.",
        "trust": "Web form submits strictly to the local verified domain."
    },
    "form_action_insecure_http": {
        "risk": "CRITICAL: Sensitive form transmits data over insecure plaintext HTTP.",
        "trust": "Form submission encrypted via HTTPS."
    },
    "script_reflection_detected": {
        "risk": "HIGH RISK: Reflected script probe returned unsanitized by the web server.",
        "trust": "Web server properly sanitizes or escapes dynamic input probes."
    },
    "has_hsts": {
        "risk": "Missing Strict-Transport-Security (HSTS) header allows SSL-stripping attacks.",
        "trust": "Strict-Transport-Security (HSTS) header enforced."
    },
    "hsts_max_age_adequate": {
        "risk": "HSTS max-age is inadequate (< 18 weeks) or improperly configured.",
        "trust": "HSTS max-age configured with strong longevity (>= 18 weeks)."
    },
    "has_csp": {
        "risk": "Missing Content-Security-Policy (CSP) exposes site to unauthorized script injection.",
        "trust": "Content-Security-Policy (CSP) actively deployed."
    },
    "csp_restricts_form_action": {
        "risk": "CSP fails to restrict form-action, allowing credential exfiltration to arbitrary endpoints.",
        "trust": "CSP explicitly restricts form-action destinations to authorized endpoints."
    },
    "csp_blocks_eval_inline": {
        "risk": "CSP permits unsafe-inline or unsafe-eval script execution.",
        "trust": "CSP prohibits unsafe inline scripts and dynamic code evaluation."
    },
    "has_x_frame_options": {
        "risk": "Missing X-Frame-Options allows page to be framed in clickjacking attacks.",
        "trust": "X-Frame-Options configured to prevent clickjacking overlays."
    },
    "x_frame_options_strict": {
        "risk": "X-Frame-Options is lenient or missing DENY/SAMEORIGIN policy.",
        "trust": "Strict X-Frame-Options (DENY/SAMEORIGIN) enforced."
    },
    "has_x_content_type_options": {
        "risk": "Missing X-Content-Type-Options: nosniff allows MIME-confusion attacks.",
        "trust": "X-Content-Type-Options: nosniff enforced."
    },
    "has_referrer_policy": {
        "risk": "Missing Referrer-Policy may leak sensitive URL parameters in HTTP referrers.",
        "trust": "Privacy-preserving Referrer-Policy configured."
    },
    "has_permissions_policy": {
        "risk": "Missing Permissions-Policy leaves browser APIs (camera, mic, geolocation) unrestricted.",
        "trust": "Permissions-Policy restricts sensitive browser device APIs."
    },
    "cookie_secure_ratio": {
        "risk": "Session cookies issued without Secure flag, exposing them over unencrypted links.",
        "trust": "All session cookies strictly enforce Secure transmission flag."
    },
    "cookie_httponly_ratio": {
        "risk": "Session cookies lack HttpOnly flag, leaving them accessible to JavaScript theft.",
        "trust": "Session cookies protected with HttpOnly flag."
    },
    "cert_valid": {
        "risk": "TLS certificate is invalid, untrusted, or has hostname verification mismatch.",
        "trust": "Valid TLS certificate verified by trusted root Certificate Authority."
    },
    "cert_is_free_or_short_lived": {
        "risk": "Disposable short-lived / automated TLS certificate typical of ephemeral phishing domains.",
        "trust": "Long-lived, established corporate TLS certificate."
    },
    "has_right_click_disabled": {
        "risk": "Anti-analysis behavior: Webpage disables right-click / context menu to hinder inspection.",
        "trust": "Normal browser context menu interaction enabled."
    },
    "has_ip_address": {
        "risk": "URL uses raw numerical IP address instead of registered domain name.",
        "trust": "URL uses standard fully-qualified domain name (FQDN)."
    },
    "is_high_risk_tld": {
        "risk": "Domain registered under high-abuse discount TLD (.xyz, .top, .tk, .cam, etc.).",
        "trust": "Domain registered under established, reputable TLD (.com, .org, .edu, .gov)."
    },
    "suspicious_keyword_count": {
        "risk": "URL string contains credential-harvesting or brand impersonation keywords.",
        "trust": "URL string does not contain suspicious lure keywords."
    },
    "title_brand_mismatch": {
        "risk": "Page title claims corporate brand identity that does not match the actual domain.",
        "trust": "Page title matches authenticated domain identity."
    },
    "has_password_input": {
        "risk": "Page renders password credential input fields.",
        "trust": "No credential harvesting input fields found."
    },
    "has_sensitive_input": {
        "risk": "Page solicits high-value sensitive data (SSN, credit card, PIN, CVV).",
        "trust": "No high-value financial or identity fields detected."
    },
    "empty_form_action_ratio": {
        "risk": "Form action is empty or points to dummy placeholder (#, javascript:void(0)).",
        "trust": "Forms specify legitimate submission endpoints."
    },
    "external_form_action_ratio": {
        "risk": "Form targets external foreign server for data processing.",
        "trust": "Form submissions routed to internal first-party servers."
    },
    "external_script_ratio": {
        "risk": "High proportion of scripts loaded from foreign third-party domains.",
        "trust": "Scripts loaded from verified first-party or reputable CDNs."
    },
    "has_double_slash_redirect": {
        "risk": "URL path contains double-slash (//) obfuscation redirect pattern.",
        "trust": "Clean URL path formatting."
    },
    "subdomain_count": {
        "risk": "Excessive subdomain nesting used to disguise destination domain.",
        "trust": "Standard subdomain hierarchy."
    },
    "entropy": {
        "risk": "High lexical randomness / entropy indicates algorithmic domain generation (DGA).",
        "trust": "Normal lexical entropy."
    }
}


@dataclass
class EvidenceSignal:
    feature_name: str
    attribution_weight: float
    raw_value: float
    signal_type: str  # "RISK" or "TRUST"
    explanation: str


@dataclass
class ExplanationReport:
    url: str
    verdict: str
    phishing_probability: float
    abstained: bool
    abstention_reason: str
    baseline_log_odds: float
    total_predicted_log_odds: float
    top_risk_signals: List[EvidenceSignal]
    top_trust_signals: List[EvidenceSignal]
    action_recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "verdict": self.verdict,
            "phishing_probability": self.phishing_probability,
            "abstained": self.abstained,
            "abstention_reason": self.abstention_reason,
            "baseline_log_odds": round(self.baseline_log_odds, 4),
            "total_predicted_log_odds": round(self.total_predicted_log_odds, 4),
            "top_risk_signals": [
                {
                    "feature": s.feature_name,
                    "weight": round(s.attribution_weight, 4),
                    "raw_value": s.raw_value,
                    "explanation": s.explanation
                }
                for s in self.top_risk_signals
            ],
            "top_trust_signals": [
                {
                    "feature": s.feature_name,
                    "weight": round(s.attribution_weight, 4),
                    "raw_value": s.raw_value,
                    "explanation": s.explanation
                }
                for s in self.top_trust_signals
            ],
            "action_recommendation": self.action_recommendation
        }


class BEAPExplainer:
    """Generates structured explanations for BEAP predictions."""

    def __init__(self, top_k: int = 5):
        self.top_k = top_k

    def generate_report(
        self,
        url: str,
        verdict: str,
        prob: float,
        abstained: bool,
        abstention_reason: str,
        attributions: Dict[str, float],
        raw_features: Dict[str, float],
        baseline_log_odds: float = 0.0,
        total_predicted_log_odds: float = 0.0
    ) -> ExplanationReport:
        """
        Builds the explanation report with top risk and trust signals.
        """
        risk_signals = []
        trust_signals = []

        for feat_name, weight in attributions.items():
            raw_val = raw_features.get(feat_name, 0.0)
            expl_dict = FEATURE_EXPLANATIONS.get(feat_name, {})

            if weight > 0.01:
                # Signal pushing toward Phishing
                text = expl_dict.get("risk", f"Feature '{feat_name}' (value={raw_val:.2f}) increased phishing score.")
                risk_signals.append(EvidenceSignal(
                    feature_name=feat_name,
                    attribution_weight=weight,
                    raw_value=raw_val,
                    signal_type="RISK",
                    explanation=text
                ))
            elif weight < -0.01:
                # Signal pushing toward Legitimate
                text = expl_dict.get("trust", f"Feature '{feat_name}' (value={raw_val:.2f}) increased legitimate score.")
                trust_signals.append(EvidenceSignal(
                    feature_name=feat_name,
                    attribution_weight=weight,
                    raw_value=raw_val,
                    signal_type="TRUST",
                    explanation=text
                ))

        # Sort by impact
        risk_signals.sort(key=lambda s: s.attribution_weight, reverse=True)
        trust_signals.sort(key=lambda s: s.attribution_weight)  # most negative first

        top_risks = risk_signals[:self.top_k]
        top_trusts = trust_signals[:self.top_k]

        # Recommendation
        if verdict == "PHISHING":
            recommendation = "BLOCK & QUARANTINE: Webpage exhibits strong indicators of credential harvesting or spoofing."
        elif verdict == "LEGITIMATE":
            recommendation = "ALLOW ACCESS: Webpage exhibits verified security posture and authentic domain characteristics."
        else:
            recommendation = "DEFER / MANUAL SOC REVIEW: Evidence is inconclusive or conflicting; isolate in secure browser sandbox."

        return ExplanationReport(
            url=url,
            verdict=verdict,
            phishing_probability=prob,
            abstained=abstained,
            abstention_reason=abstention_reason,
            baseline_log_odds=baseline_log_odds,
            total_predicted_log_odds=total_predicted_log_odds,
            top_risk_signals=top_risks,
            top_trust_signals=top_trusts,
            action_recommendation=recommendation
        )

