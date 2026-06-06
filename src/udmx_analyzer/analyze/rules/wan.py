"""WAN / internet uplink rules."""

from __future__ import annotations

from typing import Iterable, List

from ...models import Bundle, Evidence, Finding, Recommendation, Severity
from ..base import Rule, register
from .. import knowledge as kb


def _matches(bundle: Bundle, signatures) -> List:
    out = []
    for ev in bundle.log_events:
        if any(sig in ev.raw for sig in signatures):
            out.append(ev)
    return out


@register
class WanFlappingRule(Rule):
    """Detect repeated WAN link up/down transitions (an unstable uplink).

    A flapping WAN is one of the most common causes of "internet keeps
    dropping" complaints and is fully evidence-based: we count discrete
    link-state transitions in the logs.
    """

    rule_id = "WAN-FLAP"
    category = "wan"
    # Threshold: a healthy uplink should not bounce repeatedly. 4+ down events
    # across the captured window is well outside normal and rarely a false
    # positive (a single reboot produces one).
    DOWN_THRESHOLD = 4

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        downs = _matches(bundle, kb.WAN_DOWN_SIGNATURES)
        ups = _matches(bundle, kb.WAN_UP_SIGNATURES)
        if len(downs) < self.DOWN_THRESHOLD:
            return

        evidence: List[Evidence] = [ev.evidence() for ev in downs[:6]]
        if ups:
            evidence.append(ups[0].evidence())

        yield Finding(
            rule_id=self.rule_id,
            title=f"WAN uplink flapping: {len(downs)} link-down events observed",
            severity=Severity.HIGH,
            category=self.category,
            confidence=0.85,
            description=(
                f"The logs record {len(downs)} WAN link-down events and "
                f"{len(ups)} link-up events. Repeated transitions indicate an "
                "unstable physical link (cable/SFP/ISP handoff) or a "
                "renegotiating WAN port, not a configuration error by itself."
            ),
            evidence=evidence,
            tags=["connectivity", "physical"],
            recommendations=[
                Recommendation(
                    summary=(
                        "Confirm which interface is flapping and inspect its "
                        "physical link state and error counters before "
                        "changing anything."
                    ),
                    diagnostic_commands=[
                        "ssh root@<udm-ip>   # UniFi OS debug shell",
                        "# Identify WAN interface (commonly eth4/eth9/ppp0 on UDM Pro Max):",
                        "ip -br addr",
                        "ip route show default",
                        "# Link state, speed, duplex and error counters:",
                        "ethtool <wan-if>",
                        "ethtool -S <wan-if> | grep -Ei 'err|drop|crc|carrier'",
                        "# Recent kernel link events:",
                        "dmesg -T | grep -iE 'link|carrier|eth'",
                    ],
                    remediation_commands=[
                        "# Only after diagnostics point to a renegotiation issue —",
                        "# pin the WAN port speed/duplex to match the ISP handoff:",
                        "ethtool -s <wan-if> speed 1000 duplex full autoneg off",
                    ],
                    risk=(
                        "Forcing speed/duplex can break the link if it does not "
                        "match the upstream device. Verify the ISP/modem port "
                        "settings first; prefer replacing the cable/SFP."
                    ),
                    reference=kb.REFS["poe"],
                ),
            ],
            references=[
                "Check cable, SFP module, and ISP modem before software changes.",
            ],
        )
