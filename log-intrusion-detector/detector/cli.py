"""CLI: analyze an SSH auth log or web access log for intrusion signals.

Usage:
    python -m detector.cli /var/log/auth.log
    python -m detector.cli access.log --type web
    python -m detector.cli auth.log --json
"""

import argparse
import json

from .engine import analyze_log

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def format_report(report: dict) -> str:
    lines = []
    lines.append(f"File: {report['file_path']}  (detected type: {report['log_type']})")
    lines.append(f"  Lines parsed: {report['parsed_lines']}/{report['total_lines']} "
                 f"({report['coverage']:.1%} coverage)")
    lines.append(f"  Stats: {report['rule_stats']}")

    alerts = sorted(report["alerts"], key=lambda a: SEVERITY_ORDER.get(a["severity"], 9))
    if not alerts:
        lines.append("\nNo alerts.")
        return "\n".join(lines)

    lines.append(f"\n{len(alerts)} alert(s):")
    for a in alerts:
        lines.append(f"\n  [{a['severity'].upper()}] {a['alert_type']} - source: {a['source']}")
        lines.append(f"    {a['summary']}")
        if a["note"]:
            lines.append(f"    note: {a['note']}")
        for ev in a["evidence"][:3]:
            lines.append(f"      evidence: {ev}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Detect intrusion signals in SSH/web logs.")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--type", choices=["auto", "ssh", "web"], default="auto")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = analyze_log(args.logfile, log_type=args.type)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(format_report(report))


if __name__ == "__main__":
    main()
