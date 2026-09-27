"""Web access-log detection rules: path/404 scanning, known scanner
user-agents, injection patterns in the request, and request-rate floods."""

import re

from .alerts import Alert
from .windowing import find_bursts

DEFAULT_SCAN_WINDOW_SECONDS = 60
DEFAULT_SCAN_404_THRESHOLD = 15
DEFAULT_FLOOD_WINDOW_SECONDS = 10
DEFAULT_FLOOD_THRESHOLD = 50

# Named penetration-testing/scanning tools only -- deliberately NOT
# flagging generic curl/wget/python-requests, which are extremely common
# for legitimate health checks, API clients, and monitoring, and would
# make this rule mostly noise.
SCANNER_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster",
    "nessus", "acunetix", "wpscan", "hydra", "nuclei",
]

INJECTION_PATTERNS = [
    (re.compile(r"union\s+select", re.I), "SQL UNION SELECT"),
    (re.compile(r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1", re.I), "SQL tautology (OR 1=1)"),
    (re.compile(r"drop\s+table", re.I), "SQL DROP TABLE"),
    (re.compile(r"<script[\s>]", re.I), "inline <script> tag (XSS)"),
    (re.compile(r"\.\./\.\./"), "path traversal (../../)"),
    (re.compile(r"etc/passwd", re.I), "/etc/passwd reference"),
    (re.compile(r"\$\{jndi:", re.I), "JNDI lookup (Log4Shell-style)"),
]


def detect_web_alerts(
    events,
    scan_window_seconds: int = DEFAULT_SCAN_WINDOW_SECONDS,
    scan_404_threshold: int = DEFAULT_SCAN_404_THRESHOLD,
    flood_window_seconds: int = DEFAULT_FLOOD_WINDOW_SECONDS,
    flood_threshold: int = DEFAULT_FLOOD_THRESHOLD,
):
    alerts = []

    # --- path/404 scanning ---
    not_found = [(e.timestamp, e) for e in events if e.status == 404]
    scan_bursts = find_bursts(
        not_found,
        key_fn=lambda e: e.ip,
        window_seconds=scan_window_seconds,
        threshold=scan_404_threshold,
        distinct_fn=lambda e: e.path,
    )
    for ip, info in scan_bursts.items():
        paths = sorted({e.path for e in info["window_items"]})
        alerts.append(Alert(
            alert_type="path_scanning",
            severity="medium",
            source=ip,
            summary=(f"{len(paths)} distinct paths returned 404 for {ip} within "
                     f"{scan_window_seconds}s"),
            evidence=paths[:10],
            note="Consistent with automated probing for admin panels, config files, "
                 "or known-vulnerable endpoints rather than normal browsing.",
        ))

    # --- scanner user-agent ---
    seen_ua_alerts = set()
    for event in events:
        ua_lower = event.user_agent.lower()
        for tool in SCANNER_USER_AGENTS:
            if tool in ua_lower:
                key = (event.ip, tool)
                if key not in seen_ua_alerts:
                    seen_ua_alerts.add(key)
                    alerts.append(Alert(
                        alert_type="scanner_user_agent_detected",
                        severity="high",
                        source=event.ip,
                        summary=f"Request from {event.ip} identifies itself as '{tool}'",
                        evidence=[event.raw],
                        note=f"User-Agent explicitly names a security scanning tool ({tool}).",
                    ))
                break

    # --- injection patterns ---
    injection_hits = {}
    for event in events:
        target = f"{event.path}"
        for pattern, label in INJECTION_PATTERNS:
            if pattern.search(target):
                injection_hits.setdefault(event.ip, []).append((label, event))
                break

    for ip, hits in injection_hits.items():
        labels = sorted({label for label, _ in hits})
        alerts.append(Alert(
            alert_type="injection_attempt_pattern",
            severity="high",
            source=ip,
            summary=f"{len(hits)} request(s) from {ip} matched injection patterns: {', '.join(labels)}",
            evidence=[e.raw for _, e in hits[:5]],
            note="Regex-based pattern match on the request path/query string. Can false-positive "
                 "on legitimate requests that happen to contain these substrings (e.g. a search "
                 "query about SQL syntax) -- treat as a lead, not a confirmed attack.",
        ))

    # --- request-rate flood ---
    all_events = [(e.timestamp, e) for e in events]
    flood_bursts = find_bursts(
        all_events,
        key_fn=lambda e: e.ip,
        window_seconds=flood_window_seconds,
        threshold=flood_threshold,
    )
    for ip, info in flood_bursts.items():
        alerts.append(Alert(
            alert_type="high_request_rate",
            severity="medium",
            source=ip,
            summary=(f"{len(info['window_items'])} requests from {ip} within "
                     f"{flood_window_seconds}s"),
            evidence=[e.raw for e in info["window_items"][-3:]],
            note="Consistent with scraping or a denial-of-service attempt; could also be a "
                 "legitimate high-volume client (bot, load test) -- check the user-agent.",
        ))

    stats = {
        "total_events": len(events),
        "distinct_ips": len({e.ip for e in events}),
        "status_404_count": sum(1 for e in events if e.status == 404),
    }
    return alerts, stats
