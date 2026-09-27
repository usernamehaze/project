from pathlib import Path

from detector.parsers import parse_ssh_line, parse_ssh_log, parse_web_line, parse_web_log

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REAL_LOG = Path(__file__).resolve().parent.parent / "data" / "raw" / "linux_auth_sample.log"


def test_parse_modern_failed_password():
    line = "Jun 01 09:11:05 webserver01 sshd[10005]: Failed password for root from 203.0.113.50 port 445 ssh2"
    event = parse_ssh_line(line)
    assert event.outcome == "failure"
    assert event.source_ip == "203.0.113.50"
    assert event.username == "root"
    assert event.invalid_user is False


def test_parse_modern_invalid_user():
    line = "Jun 01 09:17:25 webserver01 sshd[10026]: Failed password for invalid user admin from 198.51.100.77 port 426 ssh2"
    event = parse_ssh_line(line)
    assert event.invalid_user is True
    assert event.username == "admin"


def test_parse_modern_accepted():
    line = "Jun 01 09:11:29 webserver01 sshd[10010]: Accepted password for root from 203.0.113.50 port 450 ssh2"
    event = parse_ssh_line(line)
    assert event.outcome == "success"
    assert event.source_ip == "203.0.113.50"


def test_parse_legacy_auth_failure():
    line = ("Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; "
            "logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 ")
    event = parse_ssh_line(line)
    assert event.outcome == "failure"
    assert event.source_ip == "218.188.2.4"


def test_parse_legacy_session_opened_has_no_source_ip():
    line = "Jun 17 20:29:26 combo sshd(pam_unix)[30631]: session opened for user test by (uid=509)"
    event = parse_ssh_line(line)
    assert event.outcome == "success"
    assert event.username == "test"
    assert event.source_ip is None  # documented limitation of this log format


def test_unrelated_line_returns_none():
    assert parse_ssh_line("Jun 17 20:29:26 combo su(pam_unix)[363]: session opened for user news by (uid=0)") is None
    assert parse_ssh_line("this is not a log line at all") is None


def test_real_dataset_parses_with_reasonable_coverage():
    result = parse_ssh_log(str(REAL_LOG))
    assert result.total_lines == 2000
    assert result.parsed_lines > 500
    assert 0.2 < result.coverage < 0.35


def test_parse_web_combined_log_line():
    line = ('203.0.113.10 - - [01/Jun/2025:09:00:00 +0000] "GET /about HTTP/1.1" 200 5312 '
            '"-" "Mozilla/5.0"')
    event = parse_web_line(line)
    assert event.ip == "203.0.113.10"
    assert event.path == "/about"
    assert event.status == 200
    assert event.user_agent == "Mozilla/5.0"


def test_parse_web_line_with_space_in_path():
    line = ('198.51.100.30 - - [01/Jun/2025:09:11:26 +0000] "GET /product?id=1\' OR \'1\'=\'1 '
            'HTTP/1.1" 200 4300 "-" "Mozilla/5.0"')
    event = parse_web_line(line)
    assert event is not None
    assert event.path == "/product?id=1' OR '1'='1"


def test_web_fixture_parses_at_full_coverage():
    result = parse_web_log(str(FIXTURES / "web_attack_scenarios.log"))
    assert result.coverage == 1.0
