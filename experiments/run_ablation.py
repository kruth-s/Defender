"""
Experiment 1: Comprehensive Ablation Study.
Compares four feature configurations across multiple model families on Domain-Disjoint test data:
  1. Static URL only
  2. Static URL + HTML
  3. Dynamic Browser Evidence only
  4. Full BEAP Multimodal (Static + Dynamic Browser Evidence)
"""

import os
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, brier_score_loss,
    roc_curve, precision_recall_curve
)

from beap.config import (
    STATIC_URL_FEATURES,
    STATIC_HTML_FEATURES,
    DYNAMIC_BROWSER_FEATURES,
    ALL_FEATURE_COLUMNS
)
from beap.feature_pipeline import BEAPFeaturePipeline
from beap.models import BEAPLogisticRegression, BEAPXGBoost, BEAPDecisionTree

# Configure matplotlib style
plt.rcParams.update({
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "legend.fontsize": 10,
    "figure.titlesize": 14
})


def evaluate_model(model, X_train, y_train, X_test, y_test):
    """Fits and evaluates a model, returning comprehensive metrics and curves."""
    model.fit(X_train, y_train)
    probs = model.predict_proba(X_test)
    preds = (probs >= 0.5).astype(int)

    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    roc_auc = roc_auc_score(y_test, probs)
    pr_auc = average_precision_score(y_test, probs)
    brier = brier_score_loss(y_test, probs)

    fpr, tpr, _ = roc_curve(y_test, probs)
    precision_curve, recall_curve, _ = precision_recall_curve(y_test, probs)

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "brier_score": brier,
        "fpr": fpr.tolist(),
        "tpr": tpr.tolist(),
        "curve_precision": precision_curve.tolist(),
        "curve_recall": recall_curve.tolist(),
        "probs": probs
    }


def main():
    print("=" * 60)
    print("EXPERIMENT 1: MODALITY ABLATION STUDY (DOMAIN-DISJOINT)")
    print("=" * 60)

    # Load data
    train_df = pd.read_csv(os.path.join("data", "processed", "train.csv"))
    test_df = pd.read_csv(os.path.join("data", "processed", "test.csv"))

    y_train = train_df["label"].values.astype(int)
    y_test = test_df["label"].values.astype(int)

    modalities = {
        "Static URL Only": "static_url",
        "Static URL + HTML": "static_all",
        "Dynamic Browser Only": "dynamic_only",
        "BEAP Multimodal (Proposed)": "multimodal_full"
    }

    results = []
    curves_data = {}

    for mod_name, mod_key in modalities.items():
        print(f"\nEvaluating Modality: {mod_name} ({mod_key})")
        pipeline = BEAPFeaturePipeline(feature_mode=mod_key, scale_features=True)
        X_train = pipeline.fit_transform(train_df)
        X_test = pipeline.transform(test_df)

        # 1. Logistic Regression
        lr = BEAPLogisticRegression(C=1.0)
        lr_res = evaluate_model(lr, X_train, y_train, X_test, y_test)
        results.append({
            "Modality": mod_name,
            "Classifier": "Logistic Regression",
            "Accuracy": lr_res["accuracy"],
            "Precision": lr_res["precision"],
            "Recall": lr_res["recall"],
            "F1-Score": lr_res["f1"],
            "ROC-AUC": lr_res["roc_auc"],
            "PR-AUC": lr_res["pr_auc"],
            "Brier Score": lr_res["brier_score"]
        })

        # 2. XGBoost
        xgb_model = BEAPXGBoost(n_estimators=100, max_depth=4)
        xgb_res = evaluate_model(xgb_model, X_train, y_train, X_test, y_test)
        results.append({
            "Modality": mod_name,
            "Classifier": "XGBoost",
            "Accuracy": xgb_res["accuracy"],
            "Precision": xgb_res["precision"],
            "Recall": xgb_res["recall"],
            "F1-Score": xgb_res["f1"],
            "ROC-AUC": xgb_res["roc_auc"],
            "PR-AUC": xgb_res["pr_auc"],
            "Brier Score": xgb_res["brier_score"]
        })

        curves_data[mod_name] = {
            "LR": lr_res,
            "XGB": xgb_res
        }

        print(f"  [LR]  Acc: {lr_res['accuracy']:.4f} | Rec: {lr_res['recall']:.4f} | F1: {lr_res['f1']:.4f} | AUC: {lr_res['roc_auc']:.4f}")
        print(f"  [XGB] Acc: {xgb_res['accuracy']:.4f} | Rec: {xgb_res['recall']:.4f} | F1: {xgb_res['f1']:.4f} | AUC: {xgb_res['roc_auc']:.4f}")

    results_df = pd.DataFrame(results)

    # Save tables
    os.makedirs(os.path.join("results", "tables"), exist_ok=True)
    results_df.to_csv(os.path.join("results", "tables", "ablation_results.csv"), index=False)

    # Format LaTeX table
    latex_table = results_df.to_latex(
        index=False,
        float_format="%.4f",
        caption="Ablation analysis across feature modalities under strict domain-disjoint evaluation.",
        label="tab:ablation"
    )
    with open(os.path.join("results", "tables", "ablation_table.tex"), "w") as f:
        f.write(latex_table)

    # Plot ROC and PR curves
    os.makedirs(os.path.join("results", "figures"), exist_ok=True)
    
    # 1. ROC Curves
    plt.figure(figsize=(8, 6))
    colors = ["#7f7f7f", "#1f77b4", "#ff7f0e", "#2ca02c"]
    for (mod_name, c) in zip(modalities.keys(), colors):
        lr_data = curves_data[mod_name]["LR"]
        plt.plot(
            lr_data["fpr"],
            lr_data["tpr"],
            label=f"{mod_name} (AUC = {lr_data['roc_auc']:.3f})",
            color=c,
            linewidth=2.2
        )
    plt.plot([0, 1], [0, 1], "k--", alpha=0.6, label="Random Guess")
    plt.xlabel("False Positive Rate (FPR)")
    plt.ylabel("True Positive Rate (TPR / Recall)")
    plt.title("ROC Curves: Static vs. Dynamic Browser-Augmented Detection")
    plt.legend(loc="lower right", frameon=True)
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join("results", "figures", "roc_curves.png"), dpi=300)
    plt.close()

    # 2. Precision-Recall Curves
    plt.figure(figsize=(8, 6))
    for (mod_name, c) in zip(modalities.keys(), colors):
        lr_data = curves_data[mod_name]["LR"]
        plt.plot(
            lr_data["curve_recall"],
            lr_data["curve_precision"],
            label=f"{mod_name} (PR-AUC = {lr_data['pr_auc']:.3f})",
            color=c,
            linewidth=2.2
        )
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curves Across Feature Modalities")
    plt.legend(loc="lower left", frameon=True)
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join("results", "figures", "pr_curves.png"), dpi=300)
    plt.close()

    print("\nAblation experiment completed successfully!")
    print(f"Results saved to results/tables/ and figures to results/figures/")


if __name__ == "__main__":
    main()

