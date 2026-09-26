from pathlib import Path

from forensics.qr_scanner import analyze_url, decode_qr_codes

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_decode_phishing_qr():
    payloads = decode_qr_codes(str(FIXTURES / "qr_phishing.png"))
    assert payloads == ["http://gcash-verify-account.info/login"]


def test_decode_legit_qr():
    payloads = decode_qr_codes(str(FIXTURES / "qr_legit.png"))
    assert payloads == ["https://www.wikipedia.org"]


def test_analyze_phishing_url_is_high_risk():
    result = analyze_url("http://gcash-verify-account.info/login")
    assert result["verdict"] == "high_risk"
    assert result["risk_score"] >= 40
    assert any("gcash" in s for s in result["signals"])


def test_analyze_legit_url_is_low_risk():
    result = analyze_url("https://www.wikipedia.org")
    assert result["verdict"] == "low_risk"
    assert result["risk_score"] < 15


def test_shortener_detected():
    result = analyze_url("https://bit.ly/abc123")
    assert any("shortener" in s for s in result["signals"])


def test_ip_host_detected():
    result = analyze_url("http://192.168.1.1/login")
    assert any("IP address" in s for s in result["signals"])


def test_non_url_returns_not_a_url():
    result = analyze_url("just some plain text")
    assert result["is_url"] is False
    assert result["verdict"] == "not_a_url"
