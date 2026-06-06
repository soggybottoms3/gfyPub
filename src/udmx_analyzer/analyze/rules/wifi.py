"""Wi-Fi rules: client disconnect storms and DFS radar events."""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterable, List

from ...models import Bundle, Evidence, Finding, Recommendation, Severity
from ..base import Rule, register
from .. import knowledge as kb

# "reason: 4", "reason=15", "reason code 23"
_REASON_RE = re.compile(r"reason[\s:=]+(?:code\s*)?(\d{1,2})", re.IGNORECASE)
# Disconnect/deauth phrasing UniFi APs emit. No trailing \b on purpose: we want
# to match inflected forms like "deauthenticated" and "disassociated".
_DEAUTH_RE = re.compile(
    r"\b(deauth|disassoc|disconnect|event_sta_leave|sta_leave)", re.IGNORECASE
)


@register
class WifiDeauthStormRule(Rule):
    """Detect a high volume of Wi-Fi disconnects and summarize reason codes.

    Rather than guess, this counts deauth/disassoc events and decodes the
    802.11 reason codes actually present, which point at the real cause
    (inactivity vs. 4-way handshake timeout vs. excessive frame loss).
    """

    rule_id = "WIFI-DEAUTH-STORM"
    category = "wifi"
    THRESHOLD = 10

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [ev for ev in bundle.log_events if _DEAUTH_RE.search(ev.raw)]
        if len(events) < self.THRESHOLD:
            return

        reasons: Counter = Counter()
        for ev in events:
            m = _REASON_RE.search(ev.raw)
            if m:
                reasons[int(m.group(1))] += 1

        evidence: List[Evidence] = [ev.evidence() for ev in events[:6]]
        reason_lines = []
        for code, n in reasons.most_common(5):
            desc = kb.WIFI_REASON_CODES.get(code, "Unknown / vendor-specific")
            reason_lines.append(f"  reason {code} (x{n}): {desc}")
        reason_block = "\n".join(reason_lines) if reason_lines else \
            "  (no numeric reason codes were present in the log lines)"

        # Severity scales with whether handshake/auth failures dominate.
        auth_codes = {14, 15, 16, 17, 23}
        auth_heavy = sum(reasons[c] for c in auth_codes) > (len(events) * 0.3)
        severity = Severity.HIGH if auth_heavy else Severity.MEDIUM

        yield Finding(
            rule_id=self.rule_id,
            title=f"Wi-Fi disconnect storm: {len(events)} deauth/disassoc events",
            severity=severity,
            category=self.category,
            confidence=0.8,
            description=(
                f"{len(events)} Wi-Fi disconnect events were logged. The "
                f"dominant 802.11 reason codes were:\n{reason_block}\n\n"
                "Reason 4 (inactivity) is usually benign power-saving. Codes "
                "14-17/23 indicate authentication/key-exchange failures "
                "(wrong PSK, RADIUS issue, or roaming problems). Code 5 means "
                "the AP is overloaded; code 34 indicates poor RF / frame loss."
            ),
            evidence=evidence,
            tags=["wifi", "roaming"],
            recommendations=[
                Recommendation(
                    summary=(
                        "Decode which clients/bands are affected and inspect "
                        "RF conditions before changing Wi-Fi settings."
                    ),
                    diagnostic_commands=[
                        "ssh root@<udm-ip>",
                        "# On UniFi OS, drop into the Network app container:",
                        "unifi-os shell",
                        "# Live AP/STA events and signal/noise per radio:",
                        "mca-dump | less        # full device state snapshot",
                        "# Channel utilization & interference (per AP, via SSH to the AP):",
                        "ssh <ap-ip> 'mca-cli-op info'",
                    ],
                    remediation_commands=[
                        "# If reason 5 (AP overloaded) or 34 (frame loss) dominates,",
                        "# reduce co-channel interference by fixing channels/width",
                        "# in the UniFi Network UI (Settings > WiFi > each radio).",
                        "# If auth codes (14-17/23) dominate, re-enter the WPA key",
                        "# or verify the RADIUS server reachability.",
                    ],
                    risk=(
                        "Changing channel width or minimum RSSI affects all "
                        "clients on the AP; make one change at a time and "
                        "observe."
                    ),
                    reference=kb.REFS["ieee80211"],
                ),
            ],
            references=[kb.REFS["ieee80211"]],
        )


@register
class DfsRadarRule(Rule):
    """Flag DFS radar detections that knock APs off 5 GHz channels."""

    rule_id = "WIFI-DFS-RADAR"
    category = "wifi"

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [
            ev for ev in bundle.log_events
            if any(sig.lower() in ev.raw.lower() for sig in kb.DFS_RADAR_SIGNATURES)
        ]
        # Require an explicit "radar detected" to avoid matching generic "DFS".
        radar = [ev for ev in events if "radar" in ev.raw.lower()]
        if not radar:
            return

        yield Finding(
            rule_id=self.rule_id,
            title=f"DFS radar events forced channel changes ({len(radar)} times)",
            severity=Severity.MEDIUM,
            category=self.category,
            confidence=0.9,
            description=(
                f"{len(radar)} DFS radar-detection events were logged. When an "
                "AP on a DFS 5 GHz channel detects radar it must vacate that "
                "channel immediately, briefly dropping clients. This is "
                "regulatory-mandated behavior, not a fault, but recurring hits "
                "indicate the chosen DFS channels are unusable at this location."
            ),
            evidence=[ev.evidence() for ev in radar[:6]],
            tags=["wifi", "rf", "regulatory"],
            recommendations=[
                Recommendation(
                    summary=(
                        "Move the affected radios to non-DFS 5 GHz channels to "
                        "stop the forced changes."
                    ),
                    diagnostic_commands=[
                        "ssh <ap-ip> 'mca-cli-op info'   # current channel per radio",
                    ],
                    remediation_commands=[
                        "# In UniFi Network UI: Settings > WiFi > (AP) > Radios,",
                        "# set the 5 GHz channel to a non-DFS channel",
                        "# (commonly 36/40/44/48 or 149/153/157/161 in the US),",
                        "# or disable DFS-channel auto-selection.",
                    ],
                    risk=(
                        "Non-DFS channels are fewer and more congested; balance "
                        "against interference. Allowed channels are "
                        "region-specific."
                    ),
                    reference="FCC/ETSI DFS requirements; UniFi radio settings",
                ),
            ],
        )
