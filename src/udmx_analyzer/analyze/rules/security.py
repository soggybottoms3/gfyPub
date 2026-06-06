"""Security rules: authentication brute force and IDS/IPS alerts."""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterable, List

from ...models import Bundle, Evidence, Finding, Recommendation, Severity
from ..base import Rule, register
from .. import knowledge as kb

_IP_RE = re.compile(r"(?:from|rhost=)\s*(\d{1,3}(?:\.\d{1,3}){3})")


@register
class AuthBruteForceRule(Rule):
    """Detect repeated authentication failures (possible brute force)."""

    rule_id = "SEC-AUTH-BRUTEFORCE"
    category = "security"
    THRESHOLD = 8

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [
            ev for ev in bundle.log_events
            if any(sig in ev.raw for sig in kb.AUTH_FAIL_SIGNATURES)
        ]
        if len(events) < self.THRESHOLD:
            return

        by_ip: Counter = Counter()
        for ev in events:
            m = _IP_RE.search(ev.raw)
            if m:
                by_ip[m.group(1)] += 1

        top = by_ip.most_common(5)
        src_block = (
            "\n".join(f"  {ip}: {n} failures" for ip, n in top)
            if top else "  (source IPs not present in the log lines)"
        )
        # Concentrated failures from one source are more clearly an attack.
        concentrated = bool(top) and top[0][1] >= self.THRESHOLD
        severity = Severity.HIGH if concentrated else Severity.MEDIUM

        yield Finding(
            rule_id=self.rule_id,
            title=f"Repeated authentication failures ({len(events)} attempts)",
            severity=severity,
            category=self.category,
            confidence=0.75,
            description=(
                f"{len(events)} failed authentication attempts were logged. "
                f"Top sources:\n{src_block}\n\n"
                "Concentrated failures from a single IP suggest a brute-force "
                "attempt against SSH or the management interface. Confirm "
                "whether the management plane is exposed to untrusted networks."
            ),
            evidence=[ev.evidence() for ev in events[:6]],
            tags=["security", "bruteforce"],
            recommendations=[
                Recommendation(
                    summary=(
                        "Confirm the exposure and source, then restrict "
                        "management access."
                    ),
                    diagnostic_commands=[
                        "ssh root@<udm-ip>",
                        "# Recent auth failures and their sources:",
                        "grep -iE 'failed password|invalid user' /var/log/auth.log 2>/dev/null | tail -50",
                        "# Confirm what is listening / exposed:",
                        "ss -tlnp",
                    ],
                    remediation_commands=[
                        "# Restrict the offending source at the firewall (UniFi",
                        "# Network UI: Settings > Security > Firewall), and/or",
                        "# disable SSH when not needed (Settings > System >",
                        "# Advanced > Device SSH Authentication).",
                        "# Ensure the WAN does not permit inbound 22/443 to the",
                        "# gateway management plane.",
                    ],
                    risk=(
                        "Blocking an IP that is actually a legitimate remote "
                        "admin or VPN endpoint can lock you out; verify the "
                        "source first."
                    ),
                    reference=kb.REFS["udm_ssh"],
                ),
            ],
        )


@register
class IdsIpsAlertRule(Rule):
    """Summarize IDS/IPS (Suricata) alerts present in the logs."""

    rule_id = "SEC-IDS-ALERTS"
    category = "security"
    _RE = re.compile(
        r"(suricata|\[\*\*\].*\[\*\*\]|signature_id|alert .* classification)",
        re.IGNORECASE,
    )

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [ev for ev in bundle.log_events if self._RE.search(ev.raw)]
        if not events:
            return

        yield Finding(
            rule_id=self.rule_id,
            title=f"IDS/IPS alerts logged ({len(events)} events)",
            severity=Severity.LOW,
            category=self.category,
            confidence=0.6,
            description=(
                f"{len(events)} intrusion-detection alerts are present. These "
                "are informational by themselves — they indicate the IDS/IPS "
                "engine matched a signature, which may be a genuine threat or a "
                "false positive. Review the categories and whether IPS is in "
                "detect-only or blocking mode."
            ),
            evidence=[ev.evidence() for ev in events[:6]],
            tags=["security", "ids"],
            recommendations=[
                Recommendation(
                    summary="Review alert categories in the UniFi Network UI.",
                    diagnostic_commands=[
                        "# UniFi Network UI: Insights / Security > Threats,",
                        "# filter by category and source/destination.",
                    ],
                    remediation_commands=[
                        "# Tune signature categories (Settings > Security) and",
                        "# switch IDS->IPS (blocking) only after confirming low",
                        "# false-positive rate, since IPS can drop legitimate",
                        "# traffic.",
                    ],
                    risk=(
                        "Enabling IPS blocking and DPI increases CPU/memory "
                        "load — correlate with any OOM findings before "
                        "expanding it."
                    ),
                ),
            ],
        )
