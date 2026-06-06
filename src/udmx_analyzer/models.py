"""Core data structures shared across ingestion, analysis, and reporting.

Everything downstream speaks in terms of these types. The two load-bearing
ideas:

* :class:`Bundle` is the normalized, source-agnostic view of everything that
  was ingested. Rules read from it; they never touch raw files.
* :class:`Finding` must carry one or more :class:`Evidence` items. This is the
  mechanism that keeps the tool factual — a finding with no evidence cannot be
  constructed, so a rule cannot report a problem it did not actually observe.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


class Severity(enum.IntEnum):
    """Ordered severity. IntEnum so findings sort naturally (worst first)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass(frozen=True)
class Evidence:
    """A concrete pointer back to the raw data that justifies a finding.

    At least one of these is required for every :class:`Finding`. ``locator``
    is a human-readable position within the source (e.g. ``"line 4213"`` or a
    JSON path like ``"settings.dhcpd.lease_time"``).
    """

    source: str
    locator: str
    excerpt: str
    timestamp: Optional[datetime] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "locator": self.locator,
            "excerpt": self.excerpt,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class Recommendation:
    """A factual, actionable suggestion tied to a finding.

    ``diagnostic_commands`` are read-only / non-destructive and are always
    presented first. ``remediation_commands`` change device state and carry a
    ``risk`` note. ``reference`` cites the standard or vendor doc the advice is
    grounded in.
    """

    summary: str
    diagnostic_commands: List[str] = field(default_factory=list)
    remediation_commands: List[str] = field(default_factory=list)
    risk: Optional[str] = None
    reference: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "diagnostic_commands": list(self.diagnostic_commands),
            "remediation_commands": list(self.remediation_commands),
            "risk": self.risk,
            "reference": self.reference,
        }


@dataclass
class Finding:
    """A single diagnosed issue or observation.

    ``rule_id`` is stable so findings can be suppressed or tracked over time.
    ``confidence`` is the analyzer's certainty that the evidence indicates a
    real problem (0.0-1.0), distinct from severity (how bad it is if real).
    """

    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: List[Evidence]
    recommendations: List[Recommendation] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    confidence: float = 1.0
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError(
                f"Finding {self.rule_id!r} has no evidence; findings must be "
                "backed by observed data."
            )
        self.confidence = max(0.0, min(1.0, self.confidence))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "severity_rank": int(self.severity),
            "category": self.category,
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "tags": list(self.tags),
            "evidence": [e.as_dict() for e in self.evidence],
            "recommendations": [r.as_dict() for r in self.recommendations],
            "references": list(self.references),
        }


@dataclass
class LogEvent:
    """A normalized log line from any source (syslog, plain log, journal)."""

    raw: str
    source: str
    line_no: int
    timestamp: Optional[datetime] = None
    host: Optional[str] = None
    process: Optional[str] = None
    severity_text: Optional[str] = None
    message: str = ""

    def evidence(self) -> Evidence:
        return Evidence(
            source=self.source,
            locator=f"line {self.line_no}",
            excerpt=self.raw.strip()[:500],
            timestamp=self.timestamp,
        )


@dataclass
class ConfigDoc:
    """A parsed configuration document (JSON/key-value), keyed by source name."""

    name: str
    source: str
    data: Any  # dict for JSON, dict[str,str] for key=value configs

    def evidence(self, path: str, value: Any) -> Evidence:
        return Evidence(
            source=self.source,
            locator=path,
            excerpt=f"{path} = {value!r}",
        )


@dataclass
class DeviceInfo:
    """A network device described by a support file or backup."""

    name: Optional[str] = None
    model: Optional[str] = None
    mac: Optional[str] = None
    ip: Optional[str] = None
    version: Optional[str] = None
    adopted: Optional[bool] = None
    state: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Bundle:
    """The normalized, source-agnostic view of everything ingested.

    Rules operate exclusively against this object. ``system_info`` collects
    controller/host facts (model, firmware, uptime, resource stats);
    ``warnings`` records ingestion problems (e.g. an undecryptable backup) so
    they surface to the user instead of failing silently.
    """

    sources: List[str] = field(default_factory=list)
    log_events: List[LogEvent] = field(default_factory=list)
    configs: List[ConfigDoc] = field(default_factory=list)
    devices: List[DeviceInfo] = field(default_factory=list)
    system_info: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def add_source(self, name: str) -> None:
        if name not in self.sources:
            self.sources.append(name)

    def config_by_name(self, name: str) -> Optional[ConfigDoc]:
        for c in self.configs:
            if c.name == name:
                return c
        return None

    @property
    def time_span(self):
        ts = [e.timestamp for e in self.log_events if e.timestamp]
        if not ts:
            return None
        return (min(ts), max(ts))


@dataclass
class AnalysisResult:
    """Output of an analysis run: findings plus run metadata."""

    findings: List[Finding] = field(default_factory=list)
    bundle: Optional[Bundle] = None
    generated_at: datetime = field(default_factory=datetime.now)

    def sorted_findings(self) -> List[Finding]:
        # Worst severity first, then highest confidence.
        return sorted(
            self.findings,
            key=lambda f: (int(f.severity), f.confidence),
            reverse=True,
        )

    def counts_by_severity(self) -> Dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def as_dict(self) -> Dict[str, Any]:
        b = self.bundle
        return {
            "generated_at": self.generated_at.isoformat(),
            "summary": {
                "sources": list(b.sources) if b else [],
                "log_events": len(b.log_events) if b else 0,
                "devices": len(b.devices) if b else 0,
                "counts_by_severity": self.counts_by_severity(),
                "ingest_warnings": list(b.warnings) if b else [],
            },
            "findings": [f.as_dict() for f in self.sorted_findings()],
        }
