"""Evaluate the saved model on the held-out test set and surface the
mistakes it made, for error analysis (not just aggregate metrics)."""

import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "results"


def main(show: int = 10):
    metadata_path = MODELS_DIR / "metadata.json"
    predictions_path = RESULTS_DIR / "test_predictions.csv"
    if not metadata_path.exists() or not predictions_path.exists():
        raise SystemExit("No trained model found. Run `python -m src.train` first.")

    metadata = json.loads(metadata_path.read_text())
    df = pd.read_csv(predictions_path)

    print(f"Best model: {metadata['best_model']}")
    print(f"Test set: {metadata['n_test']} messages, {metadata['n_features']} features\n")

    report = metadata["test_metrics"]["classification_report"]
    for label in ["ham", "spam"]:
        m = report[label]
        print(f"{label:>5}: precision={m['precision']:.3f} recall={m['recall']:.3f} "
              f"f1={m['f1-score']:.3f} support={int(m['support'])}")

    tn, fp = metadata["test_metrics"]["confusion_matrix"][0]
    fn, tp = metadata["test_metrics"]["confusion_matrix"][1]
    print(f"\nConfusion matrix: TN={tn} FP={fp} FN={fn} TP={tp}")

    false_positives = df[(df.true_label == "ham") & (df.pred_label == "spam")]
    false_negatives = df[(df.true_label == "spam") & (df.pred_label == "ham")]

    print(f"\n--- False positives (ham flagged as spam): {len(false_positives)} ---")
    for _, row in false_positives.head(show).iterrows():
        print(f"  [{row.source}, p={row.pred_proba_spam:.2f}] {row.text[:110]}")

    print(f"\n--- False negatives (spam missed): {len(false_negatives)} ---")
    for _, row in false_negatives.head(show).iterrows():
        print(f"  [{row.source}, p={row.pred_proba_spam:.2f}] {row.text[:110]}")


if __name__ == "__main__":
    main()
