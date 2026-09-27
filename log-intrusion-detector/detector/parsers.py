"""Parsers for two real-world log formats:

1. SSH authentication logs -- both the legacy `sshd(pam_unix)` syslog format
   (as found in the real-world Loghub Linux dataset this project ships,
   `data/raw/linux_auth_sample.log`) and the modern OpenSSH format
   (`Failed password for ... from ... port ... ssh2`).
2. Web server access logs in Common/Combined Log Format (Apache/Nginx).

Both parsers are deliberately permissive: unrecognized lines are skipped
and counted, not treated as errors, because real logs always have some
percentage of lines a given parser doesn't care about (kernel messages,
cron noise, `su` sessions in an SSH log, etc.) -- reporting a parse
coverage percentage is more honest than silently dropping lines or
crashing on them.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# The Loghub Linux sample (and syslog in general) doesn't include a year.
# All timestamps in that dataset fall within Jun-Jul of a single year with
# no December->January wraparound, so any fixed year keeps deltas correct.
SYSLOG_REFERENCE_YEAR = 2006

SYSLOG_TS_RE = re.compile(r"^([A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})")


@dataclass
class SSHEvent:
    timestamp: datetime
    outcome: str  # "failure" | "success"
    source_ip: Optional[str]
    username: Optional[str]
    invalid_user: bool
    raw: str


@dataclass
class WebEvent:
    timestamp: datetime
    ip: str
    method: str
    path: str
    status: int
    size: int
    referrer: str
    user_agent: str
    raw: str


@dataclass
class ParseResult:
    events: list
    total_lines: int
    parsed_lines: int
    skipped_lines: int

    @property
    def coverage(self) -> float:
        return self.parsed_lines / self.total_lines if self.total_lines else 0.0


def _parse_syslog_timestamp(line: str) -> Optional[datetime]:
    m = SYSLOG_TS_RE.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(f"{SYSLOG_REFERENCE_YEAR} {m.group(1)}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


# --- Legacy pam_unix format (real-world Loghub Linux dataset) ---
_LEGACY_AUTH_FAILURE_RE = re.compile(
    r"sshd\(pam_unix\)\[\d+\]: authentication failure;.*?rhost=(\S+)(?:\s+user=(\S+))?"
)
_LEGACY_SESSION_OPENED_RE = re.compile(
    r"sshd\(pam_unix\)\[\d+\]: session opened for user (\S+) by"
)

# --- Modern OpenSSH format ---
_MODERN_FAILED_RE = re.compile(
    r"sshd\[\d+\]: Failed password for (invalid user )?(\S+) from (\S+) port \d+"
)
_MODERN_ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]: Accepted password for (\S+) from (\S+) port \d+"
)


def parse_ssh_line(line: str) -> Optional[SSHEvent]:
    ts = _parse_syslog_timestamp(line)
    if ts is None:
        return None

    m = _MODERN_FAILED_RE.search(line)
    if m:
        invalid, user, ip = m.groups()
        return SSHEvent(ts, "failure", ip, user, bool(invalid), line)

    m = _MODERN_ACCEPTED_RE.search(line)
    if m:
        user, ip = m.groups()
        return SSHEvent(ts, "success", ip, user, False, line)

    m = _LEGACY_AUTH_FAILURE_RE.search(line)
    if m:
        rhost, user = m.groups()
        return SSHEvent(ts, "failure", rhost, user, user is None, line)

    m = _LEGACY_SESSION_OPENED_RE.search(line)
    if m:
        # NOTE: this legacy syslog format does not carry the source IP on
        # session-opened lines, so source_ip is deliberately None here --
        # see the README for why that limits what we can detect from it.
        return SSHEvent(ts, "success", None, m.group(1), False, line)

    return None


def parse_ssh_log(path: str) -> ParseResult:
    events = []
    total = 0
    with open(path, "r", errors="replace") as f:
        lines = [l.rstrip("\n") for l in f if l.strip()]
    total = len(lines)
    for line in lines:
        event = parse_ssh_line(line)
        if event:
            events.append(event)
    events.sort(key=lambda e: e.timestamp)
    return ParseResult(events, total, len(events), total - len(events))


# --- Web access log (Common/Combined Log Format) ---
_COMBINED_LOG_RE = re.compile(
    # `path` is non-greedy and unanchored to whitespace: a request line with
    # an unescaped literal space in the path/query (e.g. an SQL injection
    # payload like "id=1' OR '1'='1" sent without URL-encoding) is malformed
    # but real, and a naive \S+ capture truncates it at the first space and
    # fails to match the rest of the line at all -- silently dropping the
    # exact request most worth catching.
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>.*?)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)


def parse_web_line(line: str) -> Optional[WebEvent]:
    m = _COMBINED_LOG_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts").split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None
    size = m.group("size")
    return WebEvent(
        timestamp=ts,
        ip=m.group("ip"),
        method=m.group("method"),
        path=m.group("path"),
        status=int(m.group("status")),
        size=int(size) if size.isdigit() else 0,
        referrer=m.group("referrer") or "-",
        user_agent=m.group("agent") or "-",
        raw=line,
    )


def parse_web_log(path: str) -> ParseResult:
    with open(path, "r", errors="replace") as f:
        lines = [l.rstrip("\n") for l in f if l.strip()]
    total = len(lines)
    events = []
    for line in lines:
        event = parse_web_line(line)
        if event:
            events.append(event)
    events.sort(key=lambda e: e.timestamp)
    return ParseResult(events, total, len(events), total - len(events))
