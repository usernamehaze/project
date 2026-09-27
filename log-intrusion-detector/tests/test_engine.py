from pathlib import Path

from detector.engine import analyze_log, sniff_log_type

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REAL_LOG = Path(__file__).resolve().parent.parent / "data" / "raw" / "linux_auth_sample.log"


def test_sniff_detects_ssh():
    assert sniff_log_type(str(REAL_LOG)) == "ssh"
    assert sniff_log_type(str(FIXTURES / "ssh_attack_scenarios.log")) == "ssh"


def test_sniff_detects_web():
    assert sniff_log_type(str(FIXTURES / "web_attack_scenarios.log")) == "web"


def test_analyze_log_auto_detects_and_reports():
    report = analyze_log(str(FIXTURES / "ssh_attack_scenarios.log"), log_type="auto")
    assert report["log_type"] == "ssh"
    assert report["coverage"] == 1.0
    assert len(report["alerts"]) == 4


def test_analyze_log_web_auto():
    report = analyze_log(str(FIXTURES / "web_attack_scenarios.log"), log_type="auto")
    assert report["log_type"] == "web"
    assert len(report["alerts"]) == 4
