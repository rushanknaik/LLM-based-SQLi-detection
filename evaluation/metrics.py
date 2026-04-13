"""
Evaluation metrics for the hybrid detection system.
Generates confusion matrix, classification report, and accuracy.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collections import defaultdict


def classification_report(y_true, y_pred, labels=None):
    if labels is None:
        labels = sorted(set(y_true) | set(y_pred))

    stats = {}
    for label in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        support   = sum(1 for t in y_true if t == label)

        stats[label] = {
            "precision": round(precision, 3),
            "recall":    round(recall, 3),
            "f1":        round(f1, 3),
            "support":   support,
        }

    accuracy = sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true)

    return stats, round(accuracy, 4)


def confusion_matrix(y_true, y_pred, labels=None):
    if labels is None:
        labels = sorted(set(y_true) | set(y_pred))
    idx = {l: i for i, l in enumerate(labels)}
    n = len(labels)
    matrix = [[0] * n for _ in range(n)]
    for t, p in zip(y_true, y_pred):
        if t in idx and p in idx:
            matrix[idx[t]][idx[p]] += 1
    return matrix, labels


def print_report(y_true, y_pred):
    labels = sorted(set(y_true) | set(y_pred))
    stats, acc = classification_report(y_true, y_pred, labels)
    matrix, _ = confusion_matrix(y_true, y_pred, labels)

    print("\n── Classification Report ──────────────────────────")
    print(f"{'Label':<12} {'Precision':>10} {'Recall':>8} {'F1':>8} {'Support':>9}")
    print("─" * 52)
    for label, s in stats.items():
        print(f"{label:<12} {s['precision']:>10.3f} {s['recall']:>8.3f} {s['f1']:>8.3f} {s['support']:>9}")
    print(f"\nOverall Accuracy: {acc:.4f} ({acc*100:.2f}%)")

    print("\n── Confusion Matrix ───────────────────────────────")
    col_w = 12
    print(" " * col_w + "".join(f"{l:>{col_w}}" for l in labels) + "  ← Predicted")
    for i, row_label in enumerate(labels):
        print(f"{row_label:<{col_w}}" + "".join(f"{matrix[i][j]:>{col_w}}" for j in range(len(labels))))
    print("↑ Actual")