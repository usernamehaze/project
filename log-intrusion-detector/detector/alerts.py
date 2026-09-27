"""Shared Alert type produced by both the SSH and web rule sets."""

from dataclasses import dataclass, field


@dataclass
class Alert:
    alert_type: str
    severity: str  # "low" | "medium" | "high"
    source: str
    summary: str
    evidence: list = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source": self.source,
            "summary": self.summary,
            "evidence": self.evidence,
            "note": self.note,
        }
