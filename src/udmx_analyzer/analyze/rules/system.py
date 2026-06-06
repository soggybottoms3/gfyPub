"""System-health rules: out-of-memory kills, disk-full, temperature."""

from __future__ import annotations

import re
from typing import Iterable, List

from ...models import Bundle, Evidence, Finding, Recommendation, Severity
from ..base import Rule, register
from .. import knowledge as kb


@register
class OomKillerRule(Rule):
    """Detect kernel out-of-memory kills (a process was terminated for RAM)."""

    rule_id = "SYS-OOM"
    category = "system"

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [
            ev for ev in bundle.log_events
            if any(sig in ev.raw for sig in kb.OOM_SIGNATURES)
        ]
        if not events:
            return

        # Try to name the victim process(es).
        victims: List[str] = []
        for ev in events:
            m = re.search(r"Killed process \d+ \(([^)]+)\)", ev.raw)
            if m:
                victims.append(m.group(1))
        victim_text = (
            f" Killed process(es): {', '.join(sorted(set(victims)))}."
            if victims else ""
        )

        yield Finding(
            rule_id=self.rule_id,
            title=f"Out-of-memory kills detected ({len(events)} events)",
            severity=Severity.HIGH,
            category=self.category,
            confidence=0.95,
            description=(
                f"The kernel OOM killer fired {len(events)} time(s), meaning "
                "the device ran out of RAM and forcibly terminated a "
                f"process.{victim_text} On a gateway this causes service "
                "interruptions (e.g. the Network app, DPI, or IDS/IPS "
                "restarting). Frequent OOM points to a memory leak, an "
                "oversized feature set for the hardware, or insufficient RAM."
            ),
            evidence=[ev.evidence() for ev in events[:6]],
            tags=["memory", "stability"],
            recommendations=[
                Recommendation(
                    summary=(
                        "Identify the memory consumers and the cadence of OOM "
                        "events before disabling features."
                    ),
                    diagnostic_commands=[
                        "ssh root@<udm-ip>",
                        "free -h",
                        "# Top memory consumers:",
                        "ps -eo pid,ppid,rss,comm --sort=-rss | head -20",
                        "# Per-container memory (UniFi OS runs services in podman):",
                        "podman stats --no-stream",
                        "# All OOM events with context:",
                        "dmesg -T | grep -iE 'oom|killed process'",
                    ],
                    remediation_commands=[
                        "# If a specific feature (e.g. Deep Packet Inspection,",
                        "# IDS/IPS in 'high' mode) correlates with the OOM,",
                        "# reduce its scope in the UniFi Network UI.",
                        "# Restart only the affected service as a stopgap:",
                        "unifi-os restart        # restarts UniFi OS services",
                    ],
                    risk=(
                        "Restarting services briefly interrupts management and "
                        "may drop active sessions. It treats the symptom, not "
                        "the leak."
                    ),
                ),
            ],
        )


@register
class DiskFullRule(Rule):
    """Detect 'No space left on device' style storage exhaustion."""

    rule_id = "SYS-DISK-FULL"
    category = "system"

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [
            ev for ev in bundle.log_events
            if any(sig in ev.raw for sig in kb.DISK_FULL_SIGNATURES)
        ]
        if not events:
            return

        yield Finding(
            rule_id=self.rule_id,
            title=f"Storage exhaustion: 'no space left' errors ({len(events)})",
            severity=Severity.HIGH,
            category=self.category,
            confidence=0.95,
            description=(
                "One or more components failed to write because a filesystem "
                "is full. On UDM this commonly affects the data partition "
                "(logs, backups, captures) and can corrupt the Network "
                "database or stop new backups/recordings."
            ),
            evidence=[ev.evidence() for ev in events[:6]],
            tags=["storage", "stability"],
            recommendations=[
                Recommendation(
                    summary="Locate the full filesystem and the largest consumers.",
                    diagnostic_commands=[
                        "ssh root@<udm-ip>",
                        "df -h",
                        "# Largest directories on the data partition:",
                        "du -xh /data 2>/dev/null | sort -rh | head -20",
                        "# Old auto-backups often dominate:",
                        "ls -lhS /data/unifi/data/backup/autobackup/ 2>/dev/null | head",
                    ],
                    remediation_commands=[
                        "# Reduce retained auto-backups in UniFi Network UI",
                        "# (Settings > System > Backup) rather than deleting",
                        "# files blindly. If you must reclaim space immediately,",
                        "# remove the OLDEST autobackup archives only:",
                        "# rm /data/unifi/data/backup/autobackup/<oldest>.unf",
                    ],
                    risk=(
                        "Deleting the wrong files under /data can corrupt the "
                        "Network database. Never delete db.* or running state; "
                        "only remove old, explicitly-dated backup archives."
                    ),
                ),
            ],
        )


@register
class TemperatureRule(Rule):
    """Flag explicit high-temperature / thermal warnings from logs."""

    rule_id = "SYS-THERMAL"
    category = "system"
    _RE = re.compile(
        r"(temperature.*(high|critical|warning)|thermal|overheat|"
        r"throttl\w*.*temp)", re.IGNORECASE
    )

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [ev for ev in bundle.log_events if self._RE.search(ev.raw)]
        if not events:
            return

        yield Finding(
            rule_id=self.rule_id,
            title=f"Thermal warnings present ({len(events)} events)",
            severity=Severity.MEDIUM,
            category=self.category,
            confidence=0.7,
            description=(
                "The logs contain temperature/thermal warnings. Sustained high "
                "temperatures can cause throttling, instability, and reduced "
                "hardware lifespan. Verify airflow and ambient temperature."
            ),
            evidence=[ev.evidence() for ev in events[:6]],
            tags=["hardware", "thermal"],
            recommendations=[
                Recommendation(
                    summary="Read current sensor values and confirm cooling.",
                    diagnostic_commands=[
                        "ssh root@<udm-ip>",
                        "# Hardware sensors (path varies by firmware):",
                        "cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null",
                        "ubnt-device-info 2>/dev/null | grep -i temp",
                    ],
                    remediation_commands=[
                        "# No software fix: improve ventilation, clear dust from",
                        "# the chassis fan, and ensure adequate rack airflow.",
                    ],
                    risk=None,
                ),
            ],
        )
