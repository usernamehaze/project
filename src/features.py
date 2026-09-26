"""Feature engineering: TF-IDF text vectorization plus handcrafted
phishing/smishing signal features.

The handcrafted features encode the signals a human analyst would actually
look for in a smishing message: urgency language, a link, a request for
credentials/OTP, a money amount, a phone number to call/text back, shouting
(caps), etc. They matter because TF-IDF alone struggles to generalize past
the exact vocabulary it was trained on -- a brand-new scam domain or a
slightly reworded urgency phrase can slip past a purely lexical model, while
the underlying *pattern* (link + urgency + request for a code) stays the
same across campaigns and across countries.

Brand/keyword coverage spans both the Philippines (GCash, BDO, LBC, ...)
and generic international patterns (USPS/FedEx/DHL parcel scams, PayPal/
Chase/Barclays bank alerts, IRS/HMRC tax scams, E-ZPass toll scams, Netflix/
Apple ID subscription phishing, etc.) so the same model isn't tied to one
country's scam vocabulary.
"""

import re

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer

URL_RE = re.compile(
    r"(https?://\S+|www\.\S+|"
    r"\b[a-z0-9-]+\.(?:com|net|info|co|ph|org|biz|me|io|xyz|top|club|link|uk|gov|net\.ph|com\.ph|co\.uk)\b(?:/\S*)?)",
    re.IGNORECASE,
)
SHORTENED_URL_RE = re.compile(r"\b(bit\.ly|tinyurl|t\.me|goo\.gl|is\.gd|ow\.ly)\b", re.IGNORECASE)

# Deliberately generic: matches PH mobile numbers (09xxxxxxxxx / +639...) as
# well as US/UK/EU-style numbers (runs of 7-14 digits with optional +, spaces,
# dashes, or parens) rather than one country's format.
PHONE_RE = re.compile(r"(\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b")
MONEY_RE = re.compile(
    r"(₱|\$|£|€|php\s?\d|usd\s?\d|gbp\s?\d|eur\s?\d|p\s?\d{2,}(?:,\d{3})*(?:\.\d+)?)",
    re.IGNORECASE,
)
DIGIT_RE = re.compile(r"\d")

URGENCY_WORDS = [
    "urgent", "verify", "suspend", "suspended", "block", "blocked", "expire",
    "expires", "expiring", "immediately", "act now", "act fast", "claim now",
    "claim your", "limited", "locked", "deactivate", "deactivated",
    "congratulations", "winner", "won", "confirm your", "within 24 hours",
    "within 1 hour", "avoid disconnection", "avoid suspension", "reply now",
    "click here", "click the link", "final notice", "do not ignore",
]

# Philippines-specific brands/scam terms (GCash, local banks, couriers,
# telcos, government agencies) -- kept multi-word or distinctive where the
# bare word would otherwise be an ordinary Tagalog/English word (e.g. "dito"
# means "here" in Tagalog, so we match "dito telecom" rather than "dito").
PH_SCAM_KEYWORDS = [
    "gcash", "paymaya", "maya", "globe", "smart padala", "dito telecom", "tnt load",
    "bdo", "bpi", "metrobank", "unionbank", "landbank", "pnb",
    "lbc", "j&t", "jnt express", "ninja van", "flash express", "lalamove",
    "ntc", "sim registration", "otp", "mpin", "pin code",
    "pcso", "lotto", "raffle", "meralco", "pldt", "maynilad",
    "customs fee", "redelivery", "loan approved",
]

# Generic international brands/scam terms (US/UK/EU/AU/CA courier, banking,
# telco, tax-authority, toll-road, and subscription impersonation patterns).
INTL_SCAM_KEYWORDS = [
    "usps", "fedex", "ups", "dhl", "royal mail", "evri", "parcelforce",
    "canada post", "auspost", "hermes parcel",
    "paypal", "venmo", "zelle", "chase bank", "wells fargo",
    "bank of america", "citibank", "barclays", "hsbc", "natwest",
    "lloyds bank", "revolut", "monzo", "wise transfer", "cash app",
    "apple pay", "capital one",
    "at&t", "verizon", "t-mobile", "vodafone", "three mobile", "o2 mobile",
    "irs", "hmrc", "dvla", "social security administration",
    "e-zpass", "ezpass", "fastrak", "sunpass", "toll violation", "unpaid toll",
    "netflix", "apple id", "icloud", "amazon prime", "disney+",
    "whatsapp", "telegram",
    "bitcoin", "binance", "coinbase",
]

SCAM_BRAND_KEYWORDS = PH_SCAM_KEYWORDS + INTL_SCAM_KEYWORDS

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
    "num_scam_brand_keywords",
]


def _keyword_pattern(keyword: str) -> re.Pattern:
    """Word-boundary-aware pattern so short/common tokens (e.g. "ups",
    "three") don't fire on unrelated substrings like "backups" or "the
    three of us", while still matching phrases containing punctuation
    (e.g. "at&t", "e-zpass", "disney+")."""
    escaped = re.escape(keyword)
    prefix = r"\b" if keyword[0].isalnum() else ""
    suffix = r"\b" if keyword[-1].isalnum() else ""
    return re.compile(prefix + escaped + suffix, re.IGNORECASE)


_URGENCY_PATTERNS = [(_keyword_pattern(w), w) for w in URGENCY_WORDS]
_BRAND_PATTERNS = [(_keyword_pattern(w), w) for w in SCAM_BRAND_KEYWORDS]


def _shout_word_count(text: str) -> int:
    return sum(1 for w in re.findall(r"[A-Za-z]+", text) if len(w) >= 3 and w.isupper())


def extract_handcrafted_features(texts) -> np.ndarray:
    """Return an (n_samples, n_handcrafted_features) float array."""
    rows = []
    for text in texts:
        text = text or ""
        length = len(text)
        digits = len(DIGIT_RE.findall(text))
        upper_letters = sum(1 for c in text if c.isupper())
        letters = sum(1 for c in text if c.isalpha())

        rows.append([
            length,
            len(URL_RE.findall(text)),
            1.0 if URL_RE.search(text) else 0.0,
            1.0 if SHORTENED_URL_RE.search(text) else 0.0,
            digits / length if length else 0.0,
            upper_letters / letters if letters else 0.0,
            _shout_word_count(text),
            text.count("!"),
            len(MONEY_RE.findall(text)),
            len(PHONE_RE.findall(text)),
            sum(1 for pat, _ in _URGENCY_PATTERNS if pat.search(text)),
            sum(1 for pat, _ in _BRAND_PATTERNS if pat.search(text)),
        ])
    return np.asarray(rows, dtype=float)


def explain_signals(text: str) -> dict:
    """Return the handcrafted signals that fired for a single message,
    used by predict.py to show *why* a message was flagged."""
    values = extract_handcrafted_features([text])[0]
    signals = dict(zip(HANDCRAFTED_FEATURE_NAMES, values))
    signals["matched_urgency_words"] = [w for pat, w in _URGENCY_PATTERNS if pat.search(text)]
    signals["matched_scam_keywords"] = [w for pat, w in _BRAND_PATTERNS if pat.search(text)]
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
