"""CLI to classify a single SMS message and explain why.

Usage:
    python -m src.predict "GCash: Your account will be suspended, verify now: bit.ly/xyz"
"""

import argparse
import sys
from pathlib import Path

import joblib

from src.features import extract_handcrafted_features, explain_signals, hstack_features

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"


def load_artifacts():
    required = ["word_vectorizer.joblib", "char_vectorizer.joblib", "scaler.joblib", "model.joblib"]
    missing = [f for f in required if not (MODELS_DIR / f).exists()]
    if missing:
        raise SystemExit(
            f"Missing trained artifacts {missing} in {MODELS_DIR}/. Run `python -m src.train` first."
        )
    return (
        joblib.load(MODELS_DIR / "word_vectorizer.joblib"),
        joblib.load(MODELS_DIR / "char_vectorizer.joblib"),
        joblib.load(MODELS_DIR / "scaler.joblib"),
        joblib.load(MODELS_DIR / "model.joblib"),
    )


def classify(text: str, artifacts=None) -> dict:
    word_vec, char_vec, scaler, model = artifacts or load_artifacts()

    X_word = word_vec.transform([text])
    X_char = char_vec.transform([text])
    X_hand = extract_handcrafted_features([text])
    X = scaler.transform(hstack_features(X_word, X_char, X_hand))

    pred = model.predict(X)[0]
    proba_spam = model.predict_proba(X)[0, 1]
    label = "spam" if pred == 1 else "ham"

    signals = explain_signals(text)
    fired = []
    if signals["has_url"]:
        fired.append("contains a link")
    if signals["has_shortened_url"]:
        fired.append("uses a shortened URL")
    if signals["num_phone_numbers"] >= 1:
        fired.append("contains a phone number")
    if signals["matched_urgency_words"]:
        fired.append(f"urgency language: {', '.join(signals['matched_urgency_words'][:5])}")
    if signals["matched_scam_keywords"]:
        fired.append(f"scam brand/keyword match: {', '.join(signals['matched_scam_keywords'][:5])}")
    if signals["num_money_mentions"] >= 1:
        fired.append("mentions a money amount")
    if signals["uppercase_ratio"] > 0.3:
        fired.append("heavy use of CAPS")

    return {
        "text": text,
        "label": label,
        "proba_spam": float(proba_spam),
        "signals_fired": fired,
    }


def main():
    parser = argparse.ArgumentParser(description="Classify an SMS message as spam/phishing or ham.")
    parser.add_argument("message", nargs="?", help="Message text to classify")
    args = parser.parse_args()

    text = args.message
    if not text:
        if sys.stdin.isatty():
            parser.error("Provide a message as an argument or pipe it via stdin.")
        text = sys.stdin.read().strip()

    result = classify(text)
    print(f"Label: {result['label'].upper()} (P(spam)={result['proba_spam']:.3f})")
    if result["signals_fired"]:
        print("Signals:")
        for s in result["signals_fired"]:
            print(f"  - {s}")
    else:
        print("Signals: none of the heuristic flags fired; classification is driven by TF-IDF text similarity.")


if __name__ == "__main__":
    main()
