from pathlib import Path

from detector.parsers import parse_web_log
from detector.web_rules import detect_web_alerts

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_alerts():
    result = parse_web_log(str(FIXTURES / "web_attack_scenarios.log"))
    return detect_web_alerts(result.events)


def _alerts_by_source(alerts):
    by_source = {}
    for a in alerts:
        by_source.setdefault(a.source, []).append(a)
    return by_source


def test_benign_traffic_raises_no_alerts():
    alerts, _ = _load_alerts()
    flagged = {a.source for a in alerts}
    for benign_ip in ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"]:
        assert benign_ip not in flagged


def test_curl_health_check_not_flagged_as_scanner():
    """curl is common and legitimate for health checks/API clients --
    only named pentest tools (sqlmap, nikto, ...) should trigger this rule."""
    alerts, _ = _load_alerts()
    flagged = {a.source for a in alerts}
    assert "203.0.113.14" not in flagged


def test_path_scanning_detected():
    alerts, _ = _load_alerts()
    by_source = _alerts_by_source(alerts)
    assert "path_scanning" in {a.alert_type for a in by_source["198.51.100.10"]}


def test_sqlmap_user_agent_detected():
    alerts, _ = _load_alerts()
    by_source = _alerts_by_source(alerts)
    alert = next(a for a in by_source["198.51.100.20"] if a.alert_type == "scanner_user_agent_detected")
    assert "sqlmap" in alert.summary.lower()


def test_injection_patterns_detected():
    alerts, _ = _load_alerts()
    by_source = _alerts_by_source(alerts)
    alert = next(a for a in by_source["198.51.100.30"] if a.alert_type == "injection_attempt_pattern")
    assert "SQL tautology (OR 1=1)" in alert.summary
    assert "inline <script> tag (XSS)" in alert.summary
    assert "path traversal (../../)" in alert.summary


def test_high_request_rate_detected():
    alerts, _ = _load_alerts()
    by_source = _alerts_by_source(alerts)
    alert = next(a for a in by_source["198.51.100.40"] if a.alert_type == "high_request_rate")
    assert alert.severity == "medium"
