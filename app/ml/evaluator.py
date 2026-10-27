"""
Model Evaluation and Operational Threshold Calibration for EMBER Baseline Classifier.

Conforms to ETHIO-AI Defender ML-03E specifications:
- Computes ROC-AUC and Precision-Recall AUC (Average Precision).
- Calibrates operational decision thresholds on validation data at fixed FPR constraints (1.0% and 0.1%).
- Evaluates frozen model and thresholds on held-out test data.
- Explicitly documents empirical threshold limitations vs. operational base rates.
"""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    roc_curve,
)


def compute_binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> Dict[str, Any]:
    """
    Compute binary classification metrics at a given decision threshold.
    
    Args:
        y_true: Array of binary ground truth labels (0 or 1).
        y_prob: Array of predicted malicious probabilities in [0, 1].
        threshold: Decision threshold tau.
        
    Returns:
        Dict containing confusion matrix counts, precision, recall, f1, fpr, tpr.
    """
    y_pred = (y_prob >= threshold).astype(np.int32)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    
    total_benign = int(tn + fp)
    total_malicious = int(tp + fn)
    
    fpr = float(fp / total_benign) if total_benign > 0 else 0.0
    tpr = float(tp / total_malicious) if total_malicious > 0 else 0.0
    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = tpr
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = float((tp + tn) / (total_benign + total_malicious)) if (total_benign + total_malicious) > 0 else 0.0
    
    return {
        "threshold": float(threshold),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "total_benign": total_benign,
        "total_malicious": total_malicious,
        "fpr": fpr,
        "tpr": tpr,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def calibrate_operational_thresholds(
    y_val: np.ndarray,
    y_prob_val: np.ndarray,
    target_fprs: Optional[List[float]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Calibrate decision thresholds on validation data to achieve target FPR budgets.
    
    Threshold selection policy:
        Find tau* = argmax_{tau} { TPR(tau) | FPR(tau) <= target_fpr }
        
    Args:
        y_val: Ground truth binary labels for validation set.
        y_prob_val: Malicious probability predictions on validation set.
        target_fprs: List of target maximum FPR rates (default: [0.01, 0.001]).
        
    Returns:
        Dict mapping target FPR identifier to calibration results and threshold.
    """
    if target_fprs is None:
        target_fprs = [0.01, 0.001]  # 1.0% and 0.1%
        
    fpr_arr, tpr_arr, thresholds = roc_curve(y_val, y_prob_val)
    
    calibrated = {}
    for target in target_fprs:
        key = f"fpr_{str(target).replace('.', '_')}"
        # Indices where empirical validation FPR is <= target
        eligible_indices = np.where(fpr_arr <= target)[0]
        
        if len(eligible_indices) == 0:
            # If no threshold achieves <= target, select highest available threshold
            best_idx = int(np.argmax(thresholds))
        else:
            # Select eligible index with highest TPR (if tie, highest threshold)
            max_tpr = np.max(tpr_arr[eligible_indices])
            best_candidates = eligible_indices[np.where(tpr_arr[eligible_indices] == max_tpr)[0]]
            # Choose candidate with lowest FPR to be conservative
            best_idx = int(best_candidates[np.argmin(fpr_arr[best_candidates])])
            
        tau = float(thresholds[best_idx])
        # Clip threshold to valid [0.0, 1.0] range (roc_curve may set threshold[0] > 1.0)
        tau = min(max(tau, 0.0), 1.0)
        
        metrics = compute_binary_metrics(y_val, y_prob_val, threshold=tau)
        calibrated[key] = {
            "target_fpr": float(target),
            "calibrated_threshold": float(tau),
            "val_metrics": metrics,
            "threshold_selection_method": "argmax_tpr_subject_to_val_fpr_le_target",
            "operational_note": (
                "Empirical threshold selected on validation set. Operational FPR in production "
                "depends on deployment malware base rate, environment class balance, and data drift; "
                "an empirical threshold does not guarantee the exact same operational FPR in production."
            ),
        }
        
    return calibrated


def evaluate_frozen_model(
    y_test: np.ndarray,
    y_prob_test: np.ndarray,
    calibrated_thresholds: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Evaluate a frozen model and frozen thresholds on the held-out test set.
    
    Args:
        y_test: Ground truth binary labels for locked test set.
        y_prob_test: Predicted malicious probabilities for test set.
        calibrated_thresholds: Calibration dict from calibrate_operational_thresholds().
        
    Returns:
        Comprehensive evaluation report with ROC-AUC, PR-AUC, and per-threshold test metrics.
    """
    roc_auc = float(roc_auc_score(y_test, y_prob_test))
    pr_auc = float(average_precision_score(y_test, y_prob_test))
    
    threshold_evaluations = {}
    for key, cal_info in calibrated_thresholds.items():
        tau = cal_info["calibrated_threshold"]
        test_metrics = compute_binary_metrics(y_test, y_prob_test, threshold=tau)
        threshold_evaluations[key] = {
            "target_fpr": cal_info["target_fpr"],
            "frozen_threshold": float(tau),
            "test_metrics": test_metrics,
            "threshold_selection_provenance": cal_info["threshold_selection_method"],
        }
        
    # Also evaluate default 0.5 threshold
    default_50 = compute_binary_metrics(y_test, y_prob_test, threshold=0.5)
    
    return {
        "test_sample_count": len(y_test),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "default_threshold_0_5": default_50,
        "operational_thresholds": threshold_evaluations,
    }
