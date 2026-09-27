"""Orchestrates parsing + detection: auto-detects log type, runs the right
parser and rule set, and assembles one report."""

from .parsers import parse_ssh_line, parse_ssh_log, parse_web_line, parse_web_log
from .ssh_rules import detect_ssh_alerts
from .web_rules import detect_web_alerts

SNIFF_LINES = 50


def sniff_log_type(path: str) -> str:
    ssh_hits = 0
    web_hits = 0
    checked = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            if parse_ssh_line(line):
                ssh_hits += 1
            if parse_web_line(line):
                web_hits += 1
            checked += 1
            if checked >= SNIFF_LINES:
                break

    if ssh_hits == 0 and web_hits == 0:
        return "unknown"
    return "ssh" if ssh_hits >= web_hits else "web"


def analyze_log(path: str, log_type: str = "auto", **rule_kwargs) -> dict:
    if log_type == "auto":
        log_type = sniff_log_type(path)
        if log_type == "unknown":
            raise ValueError(
                f"Could not auto-detect log format for {path}. "
                "Pass --type ssh or --type web explicitly."
            )

    if log_type == "ssh":
        parse_result = parse_ssh_log(path)
        alerts, rule_stats = detect_ssh_alerts(parse_result.events, **rule_kwargs)
    elif log_type == "web":
        parse_result = parse_web_log(path)
        alerts, rule_stats = detect_web_alerts(parse_result.events, **rule_kwargs)
    else:
        raise ValueError(f"Unknown log_type: {log_type!r} (expected 'ssh', 'web', or 'auto')")

    return {
        "file_path": path,
        "log_type": log_type,
        "total_lines": parse_result.total_lines,
        "parsed_lines": parse_result.parsed_lines,
        "coverage": parse_result.coverage,
        "rule_stats": rule_stats,
        "alerts": [a.to_dict() for a in alerts],
    }
