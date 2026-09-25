import pytest

from src.predict import classify, load_artifacts

pytestmark = pytest.mark.skipif(
    not (__import__("pathlib").Path(__file__).resolve().parent.parent / "models" / "model.joblib").exists(),
    reason="requires a trained model; run `python -m src.train` first",
)


@pytest.fixture(scope="module")
def artifacts():
    return load_artifacts()


def test_obvious_phishing_flagged(artifacts):
    result = classify(
        "GCash Alert: Your account will be suspended in 24 hours. Verify now: bit.ly/gcash-verify",
        artifacts,
    )
    assert result["label"] == "spam"
    assert result["proba_spam"] > 0.5


def test_casual_message_not_flagged(artifacts):
    result = classify("Hoy tara later after work, kain tayo sa may Katipunan", artifacts)
    assert result["label"] == "ham"
    assert result["proba_spam"] < 0.5


def test_legit_transaction_notice_not_flagged(artifacts):
    result = classify(
        "You have received P500.00 from Juan Dela Cruz via GCash. Reference: 1234567890.",
        artifacts,
    )
    assert result["label"] == "ham"
