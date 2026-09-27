"""Generate a synthetic Nginx/Apache access log (Combined Log Format) with
known, labeled attack scenarios interleaved with benign traffic.

Scenarios (see tests/test_web_rules.py for the ground-truth assertions):
  - benign browsing traffic + a legit curl health-check -> NO alerts
  - 198.51.100.10: scans ~20 distinct nonexistent admin/config paths
    -> path_scanning
  - 198.51.100.20: request carries the sqlmap User-Agent
    -> scanner_user_agent_detected
  - 198.51.100.30: SQLi and XSS payloads in the query string
    -> injection_attempt_pattern
  - 198.51.100.40: 60 requests to "/" within 5 seconds
    -> high_request_rate
"""

from datetime import datetime, timedelta
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "web_attack_scenarios.log"
BASE_TIME = datetime(2025, 6, 1, 9, 0, 0)

ADMIN_PROBE_PATHS = [
    "/admin", "/administrator", "/wp-login.php", "/wp-admin", "/.env",
    "/.git/config", "/phpmyadmin", "/config.php.bak", "/backup.zip",
    "/.aws/credentials", "/server-status", "/actuator/env", "/console",
    "/cgi-bin/test", "/xmlrpc.php", "/db.sql", "/adminer.php",
    "/.svn/entries", "/debug", "/api/v1/users/dump",
]


def fmt(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


def log_line(ip, ts, method, path, status, size, referrer, agent):
    return f'{ip} - - [{fmt(ts)}] "{method} {path} HTTP/1.1" {status} {size} "{referrer}" "{agent}"'


BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def main():
    lines = []
    t = BASE_TIME

    # --- benign browsing traffic ---
    for ip, path in [
        ("203.0.113.10", "/"), ("203.0.113.10", "/about"),
        ("203.0.113.11", "/products/42"), ("203.0.113.12", "/contact"),
        ("203.0.113.11", "/products/43"), ("203.0.113.13", "/blog/post-1"),
    ]:
        lines.append(log_line(ip, t, "GET", path, 200, 5312, "-", BROWSER_UA))
        t += timedelta(seconds=20)

    # legit health-check bot using curl -- should NOT be flagged as a scanner
    for _ in range(5):
        lines.append(log_line("203.0.113.14", t, "GET", "/healthz", 200, 15, "-", "curl/8.4.0"))
        t += timedelta(minutes=1)

    # --- scenario: path/admin scanning ---
    scanner_ip = "198.51.100.10"
    for path in ADMIN_PROBE_PATHS:
        lines.append(log_line(scanner_ip, t, "GET", path, 404, 178, "-", "python-requests/2.31.0"))
        t += timedelta(seconds=1)
    t += timedelta(minutes=2)

    # --- scenario: sqlmap user-agent ---
    sqlmap_ip = "198.51.100.20"
    for path in ["/product?id=1", "/product?id=2", "/product?id=3"]:
        lines.append(log_line(sqlmap_ip, t, "GET", path, 200, 4211, "-", "sqlmap/1.7.2#stable"))
        t += timedelta(seconds=2)
    t += timedelta(minutes=2)

    # --- scenario: injection payloads ---
    inj_ip = "198.51.100.30"
    lines.append(log_line(inj_ip, t, "GET", "/product?id=1' OR '1'='1", 200, 4300, "-", BROWSER_UA))
    t += timedelta(seconds=3)
    lines.append(log_line(inj_ip, t, "GET", "/search?q=<script>alert(1)</script>", 200, 3900, "-", BROWSER_UA))
    t += timedelta(seconds=3)
    lines.append(log_line(inj_ip, t, "GET", "/files?path=../../etc/passwd", 403, 512, "-", BROWSER_UA))
    t += timedelta(minutes=2)

    # --- scenario: request-rate flood ---
    flood_ip = "198.51.100.40"
    flood_start = t
    for i in range(60):
        lines.append(log_line(flood_ip, t, "GET", "/", 200, 5312, "-", "Go-http-client/1.1"))
        t += timedelta(milliseconds=80)  # 60 requests in ~4.8s

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {OUT_PATH}")


if __name__ == "__main__":
    main()
