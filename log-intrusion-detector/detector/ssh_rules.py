"""SSH auth-log detection rules: brute force, user enumeration, and
successful-login-after-brute-force escalation."""

from .alerts import Alert
from .windowing import find_bursts

DEFAULT_WINDOW_SECONDS = 300
DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_DISTINCT_USER_THRESHOLD = 4


def detect_ssh_alerts(
    events,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    distinct_user_threshold: int = DEFAULT_DISTINCT_USER_THRESHOLD,
):
    alerts = []

    failures_with_ip = [(e.timestamp, e) for e in events if e.outcome == "failure" and e.source_ip]
    successes = [e for e in events if e.outcome == "success"]
    successes_with_ip = [e for e in successes if e.source_ip]
    successes_without_ip = len(successes) - len(successes_with_ip)

    brute_force_bursts = find_bursts(
        failures_with_ip,
        key_fn=lambda e: e.source_ip,
        window_seconds=window_seconds,
        threshold=failure_threshold,
    )
    for ip, info in brute_force_bursts.items():
        alerts.append(Alert(
            alert_type="brute_force_attempt",
            severity="medium",
            source=ip,
            summary=(f"{len(info['window_items'])} failed SSH login attempts from {ip} "
                     f"within {window_seconds}s"),
            evidence=[e.raw for e in info["window_items"][-5:]],
            note="Threshold-based burst of failed logins. Doesn't by itself confirm "
                 "compromise -- see successful_login_after_brute_force for that.",
        ))

    enumeration_candidates = [
        (e.timestamp, e) for e in events if e.outcome == "failure" and e.source_ip and e.username
    ]
    enum_bursts = find_bursts(
        enumeration_candidates,
        key_fn=lambda e: e.source_ip,
        window_seconds=window_seconds,
        threshold=distinct_user_threshold,
        distinct_fn=lambda e: e.username,
    )
    for ip, info in enum_bursts.items():
        usernames = sorted({e.username for e in info["window_items"]})
        alerts.append(Alert(
            alert_type="user_enumeration_scan",
            severity="medium",
            source=ip,
            summary=f"{len(usernames)} distinct usernames tried from {ip} within {window_seconds}s",
            evidence=usernames,
            note="Trying many different usernames from one source in a short window is "
                 "consistent with account/credential enumeration, not a single mistyped login.",
        ))

    for success in successes_with_ip:
        if success.source_ip in brute_force_bursts:
            burst = brute_force_bursts[success.source_ip]
            alerts.append(Alert(
                alert_type="successful_login_after_brute_force",
                severity="high",
                source=success.source_ip,
                summary=(f"Login succeeded from {success.source_ip} as '{success.username}' "
                         f"after {len(burst['window_items'])} failed attempts from the same source"),
                evidence=[e.raw for e in burst["window_items"][-3:]] + [success.raw],
                note="The strongest signal in this rule set: a source that was just "
                     "brute-forcing logins subsequently succeeded. Treat as likely "
                     "compromise pending investigation.",
            ))

    stats = {
        "total_events": len(events),
        "total_failures": sum(1 for e in events if e.outcome == "failure"),
        "total_successes": len(successes),
        "successes_with_unknown_source": successes_without_ip,
    }
    return alerts, stats
