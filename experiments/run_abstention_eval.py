"""
Experiment 2: Selective Abstention and Uncertainty Handling.
Evaluates the Coverage-Risk trade-off, error reduction on accepted samples,
and false-negative suppression across confidence thresholds.
"""

import os
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from beap.config import ALL_FEATURE_COLUMNS, STATIC_URL_FEATURES, STATIC_HTML_FEATURES
from beap.feature_pipeline import BEAPFeaturePipeline
from beap.models import BEAPLogisticRegression, BEAPXGBoost
from beap.abstention import AbstentionEngine

# Matplotlib styling
plt.rcParams.update({
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "legend.fontsize": 10,
    "figure.titlesize": 14
})


def main():
    print("=" * 60)
    print("EXPERIMENT 2: SELECTIVE ABSTENTION & UNCERTAINTY HANDLING")
    print("=" * 60)

    train_df = pd.read_csv(os.path.join("data", "processed", "train.csv"))
    test_df = pd.read_csv(os.path.join("data", "processed", "test.csv"))

    y_train = train_df["label"].values.astype(int)
    y_test = test_df["label"].values.astype(int)

    # We evaluate two model pipelines:
    # 1. Static Baseline (URL + HTML)
    # 2. Proposed BEAP Multimodal (Static + Dynamic Browser Evidence)
    static_pipe = BEAPFeaturePipeline(feature_mode="static_all", scale_features=True)
    X_tr_static = static_pipe.fit_transform(train_df)
    X_te_static = static_pipe.transform(test_df)
    static_model = BEAPLogisticRegression(C=1.0).fit(X_tr_static, y_train)
    static_probs = static_model.predict_proba(X_te_static)

    full_pipe = BEAPFeaturePipeline(feature_mode="multimodal_full", scale_features=True)
    X_tr_full = full_pipe.fit_transform(train_df)
    X_te_full = full_pipe.transform(test_df)
    full_model = BEAPLogisticRegression(C=1.0).fit(X_tr_full, y_train)
    full_probs = full_model.predict_proba(X_te_full)

    abstention_engine = AbstentionEngine()

    print("\nComputing Coverage-Risk Profiles...")
    static_profile = abstention_engine.evaluate_coverage_risk_curve(y_test, static_probs, num_thresholds=40)
    full_profile = abstention_engine.evaluate_coverage_risk_curve(y_test, full_probs, num_thresholds=40)

    print(f"Static Model AURC: {static_profile['aurc']:.4f}")
    print(f"BEAP Full Model AURC: {full_profile['aurc']:.4f} (Lower is better)")

    # Select representative operating points for comparison table
    tradeoff_rows = []
    operating_deltas = [0.00, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35]

    for d in operating_deltas:
        t_low = 0.5 - d
        t_high = 0.5 + d

        for name, probs in [("Static Baseline", static_probs), ("BEAP Multimodal", full_probs)]:
            accepted = (probs <= t_low) | (probs >= t_high)
            cov = float(np.mean(accepted))
            abstain_rate = 1.0 - cov

            if np.sum(accepted) > 0:
                y_acc = y_test[accepted]
                p_acc = probs[accepted]
                pred_acc = (p_acc >= 0.5).astype(int)
                acc = float(np.mean(pred_acc == y_acc))
                err = 1.0 - acc

                # FNR and FPR
                phish_mask = (y_acc == 1)
                fnr = float(np.mean(pred_acc[phish_mask] == 0)) if np.sum(phish_mask) > 0 else 0.0
                leg_mask = (y_acc == 0)
                fpr = float(np.mean(pred_acc[leg_mask] == 1)) if np.sum(leg_mask) > 0 else 0.0
            else:
                acc = 1.0
                err = 0.0
                fnr = 0.0
                fpr = 0.0

            tradeoff_rows.append({
                "Model": name,
                "Delta (Margin)": d,
                "Tau Interval": f"[{t_low:.2f}, {t_high:.2f}]",
                "Coverage (%)": cov * 100.0,
                "Abstention (%)": abstain_rate * 100.0,
                "Selective Accuracy (%)": acc * 100.0,
                "Selective Risk (%)": err * 100.0,
                "Selective FNR (%)": fnr * 100.0,
                "Selective FPR (%)": fpr * 100.0
            })

    tradeoff_df = pd.DataFrame(tradeoff_rows)
    os.makedirs(os.path.join("results", "tables"), exist_ok=True)
    tradeoff_df.to_csv(os.path.join("results", "tables", "abstention_tradeoff.csv"), index=False)

    latex_table = tradeoff_df.to_latex(
        index=False,
        float_format="%.2f",
        caption="Selective Classification performance across uncertainty thresholds.",
        label="tab:abstention_tradeoff"
    )
    with open(os.path.join("results", "tables", "abstention_tradeoff.tex"), "w") as f:
        f.write(latex_table)

    # Generate Figures
    os.makedirs(os.path.join("results", "figures"), exist_ok=True)

    # 1. Coverage vs. Selective Accuracy Curve
    plt.figure(figsize=(8, 5.5))
    plt.plot(
        np.array(static_profile["coverages"]) * 100.0,
        np.array(static_profile["selective_accuracies"]) * 100.0,
        "o-",
        label="Static Baseline (URL + HTML)",
        color="#1f77b4",
        linewidth=2,
        markersize=4
    )
    plt.plot(
        np.array(full_profile["coverages"]) * 100.0,
        np.array(full_profile["selective_accuracies"]) * 100.0,
        "s-",
        label="BEAP Multimodal (Proposed)",
        color="#2ca02c",
        linewidth=2.2,
        markersize=4
    )
    plt.xlabel("Coverage (% of test samples accepted)")
    plt.ylabel("Selective Accuracy on Accepted Samples (%)")
    plt.title("Coverage vs. Accuracy Under Selective Abstention")
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.legend(loc="lower left", frameon=True)
    plt.tight_layout()
    plt.savefig(os.path.join("results", "figures", "rejection_accuracy_curve.png"), dpi=300)
    plt.close()

    # 2. Risk-Coverage Curve (Error rate vs. Coverage)
    plt.figure(figsize=(8, 5.5))
    plt.plot(
        np.array(static_profile["coverages"]) * 100.0,
        np.array(static_profile["selective_risks"]) * 100.0,
        "o-",
        label=f"Static Baseline (AURC = {static_profile['aurc']:.3f})",
        color="#1f77b4",
        linewidth=2,
        markersize=4
    )
    plt.plot(
        np.array(full_profile["coverages"]) * 100.0,
        np.array(full_profile["selective_risks"]) * 100.0,
        "s-",
        label=f"BEAP Multimodal (AURC = {full_profile['aurc']:.3f})",
        color="#2ca02c",
        linewidth=2.2,
        markersize=4
    )
    plt.xlabel("Coverage (% of test samples accepted)")
    plt.ylabel("Selective Risk / Error Rate (%)")
    plt.title("Risk-Coverage (RC) Curve: Mitigating Classification Errors")
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.legend(loc="upper left", frameon=True)
    plt.tight_layout()
    plt.savefig(os.path.join("results", "figures", "rejection_risk_curve.png"), dpi=300)
    plt.close()

    # 3. False Negative Rate Suppression
    plt.figure(figsize=(8, 5.5))
    plt.plot(
        np.array(static_profile["coverages"]) * 100.0,
        np.array(static_profile["selective_fnrs"]) * 100.0,
        "o-",
        label="Static Baseline FNR",
        color="#d62728",
        linewidth=2,
        markersize=4
    )
    plt.plot(
        np.array(full_profile["coverages"]) * 100.0,
        np.array(full_profile["selective_fnrs"]) * 100.0,
        "s-",
        label="BEAP Multimodal FNR",
        color="#2ca02c",
        linewidth=2.2,
        markersize=4
    )
    plt.xlabel("Coverage (%)")
    plt.ylabel("Selective False Negative Rate (FNR %)")
    plt.title("Suppression of Dangerous Phishing Bypasses (FNR)")
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.legend(loc="upper left", frameon=True)
    plt.tight_layout()
    plt.savefig(os.path.join("results", "figures", "fnr_suppression_curve.png"), dpi=300)
    plt.close()

    print("\nSelective Abstention evaluation completed successfully!")
    print("Generated: rejection_accuracy_curve.png, rejection_risk_curve.png, fnr_suppression_curve.png")


if __name__ == "__main__":
    main()

