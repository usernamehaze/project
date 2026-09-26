"""Bridge to the sibling SMS phishing/smishing classifier project
(../src/predict.py) so text pulled out of an image (via OCR) or a QR code
gets the same scam classification as an actual text message would.

This is the connective tissue between the two portfolio projects: rather
than re-implementing scam-text detection here, a screenshot's OCR'd text is
just routed through the model already trained and evaluated in the sibling
project.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.predict import classify as _classify_text  # noqa: E402
from src.predict import load_artifacts as _load_sms_artifacts  # noqa: E402

_artifacts_cache = None
_load_error = None

MIN_TEXT_LENGTH = 8  # shorter than this, OCR noise dominates and the model's not meaningful


def _get_artifacts():
    global _artifacts_cache, _load_error
    if _artifacts_cache is None and _load_error is None:
        try:
            _artifacts_cache = _load_sms_artifacts()
        except SystemExit as e:
            _load_error = str(e)
    return _artifacts_cache


def classify_extracted_text(text: str) -> dict:
    """Run OCR'd (or QR-decoded) text through the trained SMS phishing
    classifier. Returns None if there's no trained model available or the
    text is too short to be meaningful."""
    text = (text or "").strip()
    if len(text) < MIN_TEXT_LENGTH:
        return {"skipped": True, "reason": "text too short to classify meaningfully"}

    artifacts = _get_artifacts()
    if artifacts is None:
        return {"skipped": True, "reason": f"phishing model unavailable: {_load_error}"}

    result = _classify_text(text, artifacts)
    result["skipped"] = False
    return result
