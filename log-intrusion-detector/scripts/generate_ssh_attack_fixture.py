"""Generate a synthetic SSH auth log (modern OpenSSH format) with known,
labeled attack scenarios interleaved with benign traffic. Used as a
ground-truth fixture for tests, since the real Loghub dataset has no
official labels to score precision/recall against.

Scenarios (see the corresponding ground-truth assertions in
tests/test_ssh_rules.py):
  - benign traffic: normal logins, should raise NO alerts
  - 203.0.113.50: rapid brute force ending in a successful login
    -> brute_force_attempt + successful_login_after_brute_force
  - 198.51.100.77: many distinct usernames tried, no success
    -> user_enumeration_scan (and likely brute_force_attempt too)
  - 203.0.113.99: only 4 failures spread over 25 minutes
    -> deliberately BELOW the 5-in-5-minutes threshold: no alert.
       Demonstrates a real limitation: slow/low-and-slow brute forcing
       evades a fixed-window threshold detector like this one.
"""

from datetime import datetime, timedelta
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "ssh_attack_scenarios.log"
HOST = "webserver01"
BASE_TIME = datetime(2025, 6, 1, 9, 0, 0)


def fmt(ts: datetime) -> str:
    return ts.strftime("%b %d %H:%M:%S")


def failed(ts, user, ip, pid, invalid=True):
    tag = "invalid user " if invalid else ""
    return f"{fmt(ts)} {HOST} sshd[{pid}]: Failed password for {tag}{user} from {ip} port 4{pid % 10000} ssh2"


def accepted(ts, user, ip, pid):
    return f"{fmt(ts)} {HOST} sshd[{pid}]: Accepted password for {user} from {ip} port 4{pid % 10000} ssh2"


def main():
    lines = []
    pid = 10000
    t = BASE_TIME

    # --- benign traffic: normal employees logging in from office IPs ---
    for ip, user in [("10.0.0.5", "alice"), ("10.0.0.6", "bob"), ("10.0.0.7", "carol")]:
        lines.append(accepted(t, user, ip, pid))
        pid += 1
        t += timedelta(minutes=3)

    # one realistic typo-then-success -- 1 failure is not a brute force
    lines.append(failed(t, "dave", "10.0.0.8", pid, invalid=False))
    pid += 1
    t += timedelta(seconds=5)
    lines.append(accepted(t, "dave", "10.0.0.8", pid))
    pid += 1
    t += timedelta(minutes=2)

    # --- scenario B: brute force ending in a successful login ---
    attacker_bf = "203.0.113.50"
    burst_start = t
    for i in range(20):
        lines.append(failed(t, "root", attacker_bf, pid, invalid=False))
        pid += 1
        t += timedelta(seconds=4)
    lines.append(accepted(t, "root", attacker_bf, pid))
    pid += 1
    t += timedelta(minutes=5)

    # --- scenario C: user enumeration, no successful login ---
    attacker_enum = "198.51.100.77"
    usernames = ["admin", "administrator", "root", "ubuntu", "oracle",
                 "postgres", "test", "guest", "ftpuser", "backup"]
    for user in usernames:
        lines.append(failed(t, user, attacker_enum, pid, invalid=True))
        pid += 1
        t += timedelta(seconds=3)
    t += timedelta(minutes=5)

    # --- scenario D: slow/evasive brute force, spread past the window ---
    attacker_slow = "203.0.113.99"
    for i in range(4):
        lines.append(failed(t, "root", attacker_slow, pid, invalid=False))
        pid += 1
        t += timedelta(minutes=8)  # 8 min apart -> never 5+ within any 5-min window

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {OUT_PATH}")


if __name__ == "__main__":
    main()
