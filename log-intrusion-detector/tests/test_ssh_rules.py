from pathlib import Path

from detector.parsers import parse_ssh_log
from detector.ssh_rules import detect_ssh_alerts

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REAL_LOG = Path(__file__).resolve().parent.parent / "data" / "raw" / "linux_auth_sample.log"


def _alerts_by_source(alerts):
    by_source = {}
    for a in alerts:
        by_source.setdefault(a.source, []).append(a)
    return by_source


def test_benign_ips_raise_no_alerts():
    result = parse_ssh_log(str(FIXTURES / "ssh_attack_scenarios.log"))
    alerts, _ = detect_ssh_alerts(result.events)
    flagged_sources = {a.source for a in alerts}
    for benign_ip in ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]:
        assert benign_ip not in flagged_sources


def test_brute_force_and_escalation_detected():
    result = parse_ssh_log(str(FIXTURES / "ssh_attack_scenarios.log"))
    alerts, _ = detect_ssh_alerts(result.events)
    by_source = _alerts_by_source(alerts)
    attacker = "203.0.113.50"
    types = {a.alert_type for a in by_source[attacker]}
    assert "brute_force_attempt" in types
    assert "successful_login_after_brute_force" in types


def test_user_enumeration_detected():
    result = parse_ssh_log(str(FIXTURES / "ssh_attack_scenarios.log"))
    alerts, _ = detect_ssh_alerts(result.events)
    by_source = _alerts_by_source(alerts)
    attacker = "198.51.100.77"
    types = {a.alert_type for a in by_source[attacker]}
    assert "user_enumeration_scan" in types
    enum_alert = next(a for a in by_source[attacker] if a.alert_type == "user_enumeration_scan")
    assert len(enum_alert.evidence) >= 4  # threshold is 4; alert fires at first crossing


def test_slow_evasive_attack_is_not_detected():
    """Documents a real limitation: 4 failures spread 8 minutes apart never
    have 5+ in any 5-minute window, so this fixed-window detector misses it."""
    result = parse_ssh_log(str(FIXTURES / "ssh_attack_scenarios.log"))
    alerts, _ = detect_ssh_alerts(result.events)
    flagged_sources = {a.source for a in alerts}
    assert "203.0.113.99" not in flagged_sources


def test_real_dataset_flags_most_but_not_all_sources():
    """Against the real Loghub dataset: verifies the detector discriminates
    (flags sources with a real burst) rather than flagging every source
    that appears at all."""
    result = parse_ssh_log(str(REAL_LOG))
    alerts, stats = detect_ssh_alerts(result.events)
    brute_force_alerts = [a for a in alerts if a.alert_type == "brute_force_attempt"]
    distinct_sources_in_log = {e.source_ip for e in result.events if e.outcome == "failure" and e.source_ip}
    assert 0 < len(brute_force_alerts) < len(distinct_sources_in_log)


def test_real_dataset_successes_have_no_known_source():
    """The real dataset's legacy log format never links a successful
    session to a source IP -- confirms detect_ssh_alerts surfaces that gap
    as a stat rather than silently guessing or crashing."""
    result = parse_ssh_log(str(REAL_LOG))
    _, stats = detect_ssh_alerts(result.events)
    assert stats["successes_with_unknown_source"] == stats["total_successes"]
    assert stats["total_successes"] > 0
