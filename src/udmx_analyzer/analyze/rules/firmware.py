"""Firmware and device-adoption rules.

Note on "outdated firmware": this tool never claims a version is outdated from
a hardcoded "latest" number (that would go stale and be unfactual). Instead it
reports the installed version as an observation, and only flags an update when
the logs themselves contain an update-available notice.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from ...models import Bundle, Evidence, Finding, Recommendation, Severity
from ..base import Rule, register


@register
class FirmwareInventoryRule(Rule):
    """Report installed firmware/version as a factual observation."""

    rule_id = "FW-INVENTORY"
    category = "firmware"

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        version = bundle.system_info.get("version")
        if not version:
            return
        source = bundle.system_info.get("_source", "support file")

        yield Finding(
            rule_id=self.rule_id,
            title=f"Installed firmware/version observed: {version}",
            severity=Severity.INFO,
            category=self.category,
            confidence=1.0,
            description=(
                f"The ingested data reports version {version!r}"
                + (
                    f" on model {bundle.system_info['model']!r}"
                    if bundle.system_info.get("model") else ""
                )
                + ". This is recorded for reference; compare it against the "
                "current release on Ubiquiti's download/release pages to decide "
                "whether an update is warranted."
            ),
            evidence=[Evidence(
                source=str(source),
                locator="system_info.version",
                excerpt=f"version = {version!r}",
            )],
            tags=["inventory"],
        )


@register
class FirmwareUpdateAvailableRule(Rule):
    """Flag explicit 'update available' notices found in the logs."""

    rule_id = "FW-UPDATE-AVAILABLE"
    category = "firmware"
    _RE = re.compile(
        r"(update available|new firmware|firmware.*available|upgrade available)",
        re.IGNORECASE,
    )

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [ev for ev in bundle.log_events if self._RE.search(ev.raw)]
        if not events:
            return

        yield Finding(
            rule_id=self.rule_id,
            title="Firmware update notice present in logs",
            severity=Severity.LOW,
            category=self.category,
            confidence=0.7,
            description=(
                "The logs contain an explicit firmware-update notice. Plan an "
                "update during a maintenance window; release notes may include "
                "fixes relevant to other findings in this report."
            ),
            evidence=[ev.evidence() for ev in events[:4]],
            tags=["firmware", "maintenance"],
            recommendations=[
                Recommendation(
                    summary="Review release notes, then update during a window.",
                    diagnostic_commands=[
                        "# UniFi OS UI > System > check for updates;",
                        "# read the changelog before applying.",
                    ],
                    remediation_commands=[
                        "# Apply via the UI (preferred). Take a backup first:",
                        "# Settings > System > Backup > Download Backup.",
                    ],
                    risk=(
                        "Firmware updates reboot the device and briefly drop all "
                        "connectivity. Always back up first."
                    ),
                ),
            ],
        )


@register
class AdoptionFailureRule(Rule):
    """Detect APs/switches failing adoption or stuck disconnected."""

    rule_id = "DEV-ADOPTION-FAILURE"
    category = "firmware"
    _RE = re.compile(
        r"(adoption failed|adopt failed|failed to adopt|TLS error.*inform|"
        r"connection refused.*8080)", re.IGNORECASE,
    )

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        log_events = [ev for ev in bundle.log_events if self._RE.search(ev.raw)]

        # Also surface devices reported in a failed/disconnected state.
        bad_states = {"adoption-failed", "disconnected", "heartbeat-missed",
                      "isolated"}
        bad_devices = [
            d for d in bundle.devices
            if d.state in bad_states or d.adopted is False
        ]

        if not log_events and not bad_devices:
            return

        evidence = [ev.evidence() for ev in log_events[:4]]
        for d in bad_devices[:4]:
            evidence.append(Evidence(
                source=str(d.extra.get("_source", "device inventory")),
                locator=f"device {d.mac or d.name or '?'}",
                excerpt=(
                    f"name={d.name!r} model={d.model!r} state={d.state!r} "
                    f"adopted={d.adopted!r}"
                ),
            ))
        if not evidence:
            return

        state_counts = Counter(d.state for d in bad_devices)
        state_text = ", ".join(f"{s}: {n}" for s, n in state_counts.items()) \
            if state_counts else "none"

        yield Finding(
            rule_id=self.rule_id,
            title="Device adoption/connectivity problems",
            severity=Severity.MEDIUM,
            category=self.category,
            confidence=0.75,
            description=(
                f"{len(log_events)} adoption-failure log events and "
                f"{len(bad_devices)} device(s) in a problem state "
                f"({state_text}) were observed. Common causes: the device "
                "cannot reach the controller inform URL (TCP 8080), an L3 "
                "adoption needs 'set-inform', or a firmware mismatch."
            ),
            evidence=evidence,
            tags=["adoption", "provisioning"],
            recommendations=[
                Recommendation(
                    summary=(
                        "Verify the device can reach the inform endpoint and "
                        "re-point it if needed."
                    ),
                    diagnostic_commands=[
                        "ssh <device-ip>            # SSH to the AP/switch itself",
                        "info                       # shows adoption state + inform URL",
                        "# From the device, confirm controller reachability:",
                        "ping <controller-ip>",
                        "# Controller listens for inform on TCP 8080:",
                        "ssh root@<udm-ip> 'ss -tlnp | grep 8080'",
                    ],
                    remediation_commands=[
                        "# On the device shell, point it at the controller:",
                        "set-inform http://<controller-ip>:8080/inform",
                        "# (run twice; then click Adopt in the UI)",
                    ],
                    risk=(
                        "An incorrect inform URL leaves the device unmanaged. "
                        "For a device already adopted elsewhere, factory-reset "
                        "before re-adopting."
                    ),
                ),
            ],
        )
