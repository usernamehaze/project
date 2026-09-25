"""Train and compare phishing/smishing classifiers.

Compares Multinomial Naive Bayes, Logistic Regression, and a linear SVM via
5-fold cross-validation on the training split (scored on F1 for the spam
class, since spam is the minority class and that's the one we actually care
about catching). The best model is refit on the full training set,
evaluated once on the held-out test set, and saved to disk along with the
fitted vectorizers.
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC

from src.data_loader import load_combined_dataset, train_test_split_df
from src.features import (
    build_char_vectorizer,
    build_word_vectorizer,
    extract_handcrafted_features,
    hstack_features,
)

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "results"


def build_candidate_models():
    return {
        "naive_bayes": MultinomialNB(),
        "logistic_regression": LogisticRegression(
            max_iter=2000, class_weight="balanced", C=1.0
        ),
        "linear_svm": LinearSVC(class_weight="balanced", C=1.0, max_iter=5000),
    }


def main(seed: int = 42):
    MODELS_DIR.mkdir(exist_ok=True)
    RESULTS_DIR.mkdir(exist_ok=True)

    df = load_combined_dataset()
    train_df, test_df = train_test_split_df(df, test_size=0.2, seed=seed)

    y_train = (train_df["label"] == "spam").astype(int).values
    y_test = (test_df["label"] == "spam").astype(int).values

    print(f"Train: {len(train_df)} ({y_train.mean():.1%} spam) | "
          f"Test: {len(test_df)} ({y_test.mean():.1%} spam)")

    word_vec = build_word_vectorizer()
    char_vec = build_char_vectorizer()

    X_train_word = word_vec.fit_transform(train_df["text"])
    X_train_char = char_vec.fit_transform(train_df["text"])
    X_train_hand = extract_handcrafted_features(train_df["text"])
    X_train_raw = hstack_features(X_train_word, X_train_char, X_train_hand)

    X_test_word = word_vec.transform(test_df["text"])
    X_test_char = char_vec.transform(test_df["text"])
    X_test_hand = extract_handcrafted_features(test_df["text"])
    X_test_raw = hstack_features(X_test_word, X_test_char, X_test_hand)

    # The handcrafted features (e.g. raw message length, up to ~500) live on
    # a completely different scale than the TF-IDF columns (roughly 0-1),
    # which made LinearSVC fail to converge even at max_iter=5000. Scaling
    # every column by its train-set max magnitude (sparsity-preserving,
    # unlike StandardScaler) fixes convergence and is the correct thing to
    # do for any margin-based / gradient-based model regardless.
    scaler = MaxAbsScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    print(f"Feature matrix: {X_train.shape[1]} features "
          f"({X_train_word.shape[1]} word + {X_train_char.shape[1]} char + "
          f"{X_train_hand.shape[1]} handcrafted)")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    cv_results = {}
    for name, model in build_candidate_models().items():
        scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
        cv_results[name] = {"mean_f1": float(scores.mean()), "std_f1": float(scores.std()),
                             "fold_scores": scores.tolist()}
        print(f"  {name}: F1 = {scores.mean():.4f} (+/- {scores.std():.4f})")

    best_name = max(cv_results, key=lambda k: cv_results[k]["mean_f1"])
    print(f"\nBest model by CV F1: {best_name}")

    best_model = build_candidate_models()[best_name]
    if best_name == "linear_svm":
        # LinearSVC has no predict_proba; calibrate so predict.py can report
        # a confidence score, not just a hard label.
        best_model = CalibratedClassifierCV(best_model, cv=3)
    best_model.fit(X_train, y_train)

    y_pred = best_model.predict(X_test)
    y_proba = best_model.predict_proba(X_test)[:, 1]

    report = classification_report(y_test, y_pred, target_names=["ham", "spam"], output_dict=True)
    cm = confusion_matrix(y_test, y_pred).tolist()
    test_f1 = f1_score(y_test, y_pred)

    print("\nHeld-out test set performance:")
    print(classification_report(y_test, y_pred, target_names=["ham", "spam"]))
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(np.array(cm))

    joblib.dump(word_vec, MODELS_DIR / "word_vectorizer.joblib")
    joblib.dump(char_vec, MODELS_DIR / "char_vectorizer.joblib")
    joblib.dump(scaler, MODELS_DIR / "scaler.joblib")
    joblib.dump(best_model, MODELS_DIR / "model.joblib")

    metadata = {
        "best_model": best_name,
        "seed": seed,
        "cv_results": cv_results,
        "test_metrics": {
            "classification_report": report,
            "confusion_matrix": cm,
            "f1_spam": test_f1,
        },
        "n_train": len(train_df),
        "n_test": len(test_df),
        "n_features": X_train.shape[1],
    }
    with (MODELS_DIR / "metadata.json").open("w") as f:
        json.dump(metadata, f, indent=2)
    with (RESULTS_DIR / "metrics.json").open("w") as f:
        json.dump(metadata, f, indent=2)

    test_out = test_df.copy()
    test_out["true_label"] = np.where(y_test == 1, "spam", "ham")
    test_out["pred_label"] = np.where(y_pred == 1, "spam", "ham")
    test_out["pred_proba_spam"] = y_proba
    test_out.to_csv(RESULTS_DIR / "test_predictions.csv", index=False)

    print(f"\nSaved model + vectorizers to {MODELS_DIR}/")
    print(f"Saved metrics + predictions to {RESULTS_DIR}/")


if __name__ == "__main__":
    main()
