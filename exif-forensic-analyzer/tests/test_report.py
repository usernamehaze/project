from pathlib import Path

import pytest

from forensics.report import build_report

FIXTURES = Path(__file__).resolve().parent / "fixtures"

MODEL_PRESENT = (
    Path(__file__).resolve().parents[2] / "models" / "model.joblib"
).exists()
pytestmark = pytest.mark.skipif(
    not MODEL_PRESENT,
    reason="requires the sibling phishing model at ../models/model.joblib",
)


def test_phishing_screenshot_flagged_end_to_end():
    report = build_report(str(FIXTURES / "phishing_screenshot.png"))
    assert report["flagged"] is True
    assert report["ocr"]["classification"]["label"] == "spam"
    assert "gcash" in report["ocr"]["text"].lower()


def test_legit_screenshot_not_flagged():
    report = build_report(str(FIXTURES / "legit_screenshot.png"))
    assert report["ocr"]["classification"]["label"] == "ham"
    # no_exif_data alone shouldn't trip the overall verdict
    assert report["flagged"] is False


def test_clean_photo_not_flagged():
    report = build_report(str(FIXTURES / "clean_photo.jpg"))
    assert report["flagged"] is False


def test_qr_phishing_flagged_end_to_end():
    report = build_report(str(FIXTURES / "qr_phishing.png"))
    assert report["flagged"] is True
    assert report["qr_codes"][0]["url_analysis"]["verdict"] == "high_risk"


def test_qr_legit_not_flagged():
    report = build_report(str(FIXTURES / "qr_legit.png"))
    assert report["flagged"] is False
