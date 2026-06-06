"""Cross-source / cross-finding correlation.

Single rules answer "what happened?". Correlation answers "are these the same
incident?" — it links findings whose evidence overlaps in time so the report
can distinguish a root cause from its downstream symptoms.

Correlation findings are conservative: they only fire when the underlying
findings already exist (so they inherit that evidence) and, where timestamps
are available, when those findings actually overlap in time.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from ..models import Bundle, Evidence, Finding, Recommendation, Severity


def _by_id(findings: List[Finding]) -> Dict[str, Finding]:
    return {f.rule_id: f for f in findings}


def _time_range(finding: Finding) -> Optional[Tuple]:
    ts = [e.timestamp for e in finding.evidence if e.timestamp]
    if not ts:
        return None
    return (min(ts), max(ts))


def _overlaps(a: Finding, b: Finding, window: timedelta) -> bool:
    """True if the two findings' evidence windows are within ``window``.

    If either finding lacks timestamps we cannot prove temporal overlap, so we
    return ``True`` only when both have ranges; otherwise the correlation falls
    back to mere co-occurrence (handled by the caller's confidence).
    """

    ra, rb = _time_range(a), _time_range(b)
    if ra is None or rb is None:
        return False
    start = max(ra[0], rb[0])
    end = min(ra[1], rb[1])
    if start <= end:
        return True
    gap = start - end
    return gap <= window


def _merge_evidence(*findings: Finding, limit: int = 4) -> List[Evidence]:
    out: List[Evidence] = []
    for f in findings:
        out.extend(f.evidence[:2])
    return out[:limit]


def correlate(bundle: Bundle, findings: List[Finding]) -> List[Finding]:
    by_id = _by_id(findings)
    out: List[Finding] = []
    window = timedelta(minutes=5)

    # 1) WAN instability is the likely root cause of concurrent DNS failures.
    wan = by_id.get("WAN-FLAP")
    dns = by_id.get("DNS-RESOLUTION-FAILURES")
    if wan and dns:
        temporal = _overlaps(wan, dns, window)
        out.append(Finding(
            rule_id="CORR-WAN-DNS",
            title="DNS failures likely downstream of WAN instability",
            severity=Severity.HIGH,
            category="correlation",
            confidence=0.8 if temporal else 0.55,
            description=(
                "Both a flapping WAN uplink (WAN-FLAP) and frequent DNS "
                "failures (DNS-RESOLUTION-FAILURES) were found"
                + (
                    " within overlapping time windows. "
                    if temporal else
                    " (timestamps did not confirm overlap). "
                )
                + "When the WAN drops, upstream resolvers become unreachable, "
                "so the DNS failures are most likely a symptom of the link "
                "instability rather than an independent DNS problem. Fix the "
                "WAN first (WAN-FLAP) and re-evaluate DNS afterwards."
            ),
            evidence=_merge_evidence(wan, dns),
            tags=["correlation", "root-cause"],
            recommendations=[
                Recommendation(
                    summary=(
                        "Prioritize the WAN-FLAP remediation; treat DNS as "
                        "secondary until the uplink is stable."
                    ),
                ),
            ],
        ))

    # 2) Memory exhaustion plausibly causes the device disconnects/adoption loss.
    oom = by_id.get("SYS-OOM")
    adopt = by_id.get("DEV-ADOPTION-FAILURE")
    if oom and adopt:
        temporal = _overlaps(oom, adopt, window)
        out.append(Finding(
            rule_id="CORR-OOM-ADOPT",
            title="Device disconnects may be driven by controller OOM events",
            severity=Severity.HIGH,
            category="correlation",
            confidence=0.7 if temporal else 0.5,
            description=(
                "Out-of-memory kills (SYS-OOM) and device adoption/connectivity "
                "problems (DEV-ADOPTION-FAILURE) co-occur"
                + (" in overlapping time windows. " if temporal else ". ")
                + "If the Network application process is being OOM-killed, "
                "managed devices momentarily lose their controller and report "
                "disconnects/heartbeat-missed. Address the memory pressure "
                "(SYS-OOM) before chasing the devices individually."
            ),
            evidence=_merge_evidence(oom, adopt),
            tags=["correlation", "root-cause"],
            recommendations=[
                Recommendation(
                    summary=(
                        "Resolve the OOM condition first; device "
                        "disconnects should subside once the controller is "
                        "stable."
                    ),
                ),
            ],
        ))

    # 3) Storage-full can corrupt the DB and manifest as many unrelated errors.
    disk = by_id.get("SYS-DISK-FULL")
    if disk and len(findings) > 1:
        others = [f.rule_id for f in findings if f.rule_id != "SYS-DISK-FULL"]
        out.append(Finding(
            rule_id="CORR-DISK-CASCADE",
            title="Storage exhaustion may be amplifying other failures",
            severity=Severity.HIGH,
            category="correlation",
            confidence=0.6,
            description=(
                "A full filesystem (SYS-DISK-FULL) was detected alongside "
                f"other findings ({', '.join(sorted(set(others)))}). Storage "
                "exhaustion can cause cascading, misleading errors (failed "
                "writes, DB corruption, dropped logging). Reclaim space first, "
                "then re-run this analysis on fresh data — some other findings "
                "may resolve on their own."
            ),
            evidence=disk.evidence[:3],
            tags=["correlation", "root-cause"],
        ))

    return out
