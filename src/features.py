"""Feature engineering: TF-IDF text vectorization plus handcrafted
phishing/smishing signal features.

The handcrafted features encode the signals a human analyst would actually
look for in a smishing message: urgency language, a link, a request for
credentials/OTP, a money amount, a phone number to call/text back, shouting
(caps), etc. They matter because TF-IDF alone struggles to generalize past
the exact vocabulary it was trained on -- a brand-new scam domain or a
slightly reworded urgency phrase can slip past a purely lexical model, while
the underlying *pattern* (link + urgency + request for a code) stays the
same across campaigns.
"""

import re

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer

URL_RE = re.compile(
    r"(https?://\S+|www\.\S+|\b[a-z0-9-]+\.(?:com|net|info|co|ph|net\.ph|com\.ph)\b(?:/\S*)?)",
    re.IGNORECASE,
)
SHORTENED_URL_RE = re.compile(r"\b(bit\.ly|tinyurl|t\.me|goo\.gl)\b", re.IGNORECASE)
PH_PHONE_RE = re.compile(r"(\+?63|0)9\d{9}\b")
MONEY_RE = re.compile(r"(₱|php\s?\d|p\s?\d{2,}(?:,\d{3})*(?:\.\d+)?)", re.IGNORECASE)
DIGIT_RE = re.compile(r"\d")

URGENCY_WORDS = [
    "urgent", "verify", "suspend", "suspended", "block", "blocked", "expire",
    "expires", "expiring", "immediately", "act now", "act fast", "claim now",
    "claim your", "limited", "locked", "deactivate", "deactivated",
    "congratulations", "winner", "won", "confirm your", "within 24 hours",
    "within 1 hour", "avoid disconnection", "avoid suspension", "reply now",
    "click here", "click the link", "final notice", "do not ignore",
]

PH_SCAM_KEYWORDS = [
    "gcash", "paymaya", "maya", "globe", "smart", "dito", "tnt",
    "bdo", "bpi", "metrobank", "unionbank", "landbank", "pnb",
    "lbc", "j&t", "jnt", "ninja van", "flash express", "lalamove",
    "ntc", "sim registration", "otp", "mpin", "pin code",
    "pcso", "lotto", "raffle", "meralco", "pldt", "maynilad",
    "customs", "redelivery", "collateral", "loan approved",
]

HANDCRAFTED_FEATURE_NAMES = [
    "length",
    "num_urls",
    "has_url",
    "has_shortened_url",
    "digit_ratio",
    "uppercase_ratio",
    "num_shout_words",
    "num_exclamations",
    "num_money_mentions",
    "num_phone_numbers",
    "num_urgency_words",
    "num_ph_scam_keywords",
]


def _shout_word_count(text: str) -> int:
    return sum(1 for w in re.findall(r"[A-Za-z]+", text) if len(w) >= 3 and w.isupper())


def extract_handcrafted_features(texts) -> np.ndarray:
    """Return an (n_samples, n_handcrafted_features) float array."""
    rows = []
    for text in texts:
        text = text or ""
        lower = text.lower()
        length = len(text)
        digits = len(DIGIT_RE.findall(text))
        upper_letters = sum(1 for c in text if c.isupper())
        letters = sum(1 for c in text if c.isalpha())

        rows.append([
            length,
            len(URL_RE.findall(text)),
            1.0 if URL_RE.search(text) else 0.0,
            1.0 if SHORTENED_URL_RE.search(lower) else 0.0,
            digits / length if length else 0.0,
            upper_letters / letters if letters else 0.0,
            _shout_word_count(text),
            text.count("!"),
            len(MONEY_RE.findall(lower)),
            len(PH_PHONE_RE.findall(text)),
            sum(1 for kw in URGENCY_WORDS if kw in lower),
            sum(1 for kw in PH_SCAM_KEYWORDS if kw in lower),
        ])
    return np.asarray(rows, dtype=float)


def explain_signals(text: str) -> dict:
    """Return the handcrafted signals that fired for a single message,
    used by predict.py to show *why* a message was flagged."""
    values = extract_handcrafted_features([text])[0]
    lower = text.lower()
    signals = dict(zip(HANDCRAFTED_FEATURE_NAMES, values))
    signals["matched_urgency_words"] = [w for w in URGENCY_WORDS if w in lower]
    signals["matched_ph_keywords"] = [w for w in PH_SCAM_KEYWORDS if w in lower]
    return signals


class HandcraftedFeatureExtractor(BaseEstimator, TransformerMixin):
    """sklearn-compatible transformer wrapping extract_handcrafted_features."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return extract_handcrafted_features(X)

    def get_feature_names_out(self, input_features=None):
        return np.array(HANDCRAFTED_FEATURE_NAMES)


def build_word_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        sublinear_tf=True,
        lowercase=True,
    )


def build_char_vectorizer() -> TfidfVectorizer:
    """Char n-grams catch obfuscation (e.g. 'g-c-a-s-h', 'fr33 l0ad')
    that word-level tokenization misses."""
    return TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=3,
        max_df=0.95,
        sublinear_tf=True,
    )


def hstack_features(*matrices):
    return sparse.hstack([sparse.csr_matrix(m) for m in matrices]).tocsr()
