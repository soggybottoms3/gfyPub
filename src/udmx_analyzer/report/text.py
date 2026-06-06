"""Terminal report renderer.

Plain text with optional ANSI color (auto-disabled when output is not a TTY).
The layout leads with a severity summary, then each finding with its evidence
(the factual anchor), then read-only diagnostics, then any state-changing
remediation clearly separated and risk-annotated.
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional

from ..models import AnalysisResult, Finding, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",  # white on red
    Severity.HIGH: "\033[1;31m",          # bold red
    Severity.MEDIUM: "\033[1;33m",        # bold yellow
    Severity.LOW: "\033[1;36m",           # bold cyan
    Severity.INFO: "\033[1;90m",          # grey
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _c(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def render_text(result: AnalysisResult, color: Optional[bool] = None,
                stream=None) -> str:
    stream = stream or sys.stdout
    if color is None:
        color = _use_color(stream)

    lines: List[str] = []
    b = result.bundle

    lines.append(_c("UniFi Dream Machine Pro Max — Analysis Report", _BOLD, color))
    lines.append(f"Generated: {result.generated_at.isoformat(timespec='seconds')}")
    if b:
        lines.append(f"Sources ingested: {len(b.sources)}")
        for s in b.sources:
            lines.append(f"  - {s}")
        lines.append(f"Log events parsed: {len(b.log_events)}")
        span = b.time_span
        if span:
            lines.append(
                f"Log time span: {span[0].isoformat(timespec='seconds')} "
                f"-> {span[1].isoformat(timespec='seconds')}"
            )
        if b.system_info.get("model") or b.system_info.get("version"):
            lines.append(
                f"Device: model={b.system_info.get('model')} "
                f"version={b.system_info.get('version')}"
            )

    # Severity summary.
    counts = result.counts_by_severity()
    summary = "  ".join(
        _c(f"{sev.label}: {counts[sev.label]}", _COLORS[sev], color)
        for sev in sorted(Severity, reverse=True)
    )
    lines.append("")
    lines.append(_c("Summary by severity:", _BOLD, color))
    lines.append("  " + summary)

    if b and b.warnings:
        lines.append("")
        lines.append(_c("Ingest warnings:", _BOLD, color))
        for w in b.warnings:
            lines.append(f"  ! {w}")

    findings = result.sorted_findings()
    if not findings:
        lines.append("")
        lines.append(_c("No issues detected in the supplied data.", _BOLD, color))
        return "\n".join(lines)

    lines.append("")
    lines.append(_c(f"Findings ({len(findings)}):", _BOLD, color))
    for i, f in enumerate(findings, 1):
        lines.extend(_render_finding(i, f, color))

    return "\n".join(lines)


def _render_finding(idx: int, f: Finding, color: bool) -> List[str]:
    out: List[str] = []
    sev = _c(f"[{f.severity.label.upper()}]", _COLORS[f.severity], color)
    out.append("")
    out.append(
        f"{idx}. {sev} {_c(f.title, _BOLD, color)}  "
        f"({f.rule_id}, confidence {f.confidence:.0%}, {f.category})"
    )
    # Wrap description simply.
    for para in f.description.split("\n"):
        out.append(f"   {para}")

    out.append(f"   {_c('Evidence:', _BOLD, color)}")
    for e in f.evidence:
        ts = f" @ {e.timestamp.isoformat(timespec='seconds')}" if e.timestamp else ""
        out.append(f"     - {e.source} ({e.locator}){ts}")
        out.append(f"       {e.excerpt}")

    for r in f.recommendations:
        out.append(f"   {_c('Recommendation:', _BOLD, color)} {r.summary}")
        if r.diagnostic_commands:
            out.append(f"     {_c('Diagnostics (read-only):', _BOLD, color)}")
            for cmd in r.diagnostic_commands:
                out.append(f"       $ {cmd}")
        if r.remediation_commands:
            out.append(f"     {_c('Remediation (changes state):', _COLORS[Severity.MEDIUM], color)}")
            for cmd in r.remediation_commands:
                out.append(f"       $ {cmd}")
        if r.risk:
            out.append(f"     {_c('Risk:', _COLORS[Severity.HIGH], color)} {r.risk}")
        if r.reference:
            out.append(f"     Ref: {r.reference}")

    if f.references:
        out.append(f"   References: {'; '.join(f.references)}")
    return out
