"""Configuration-driven rules.

These read parsed config documents (not logs) and flag settings that are
factually risky. To stay non-speculative, each rule only fires on an
explicit, unambiguous value present in a config the user supplied.
"""

from __future__ import annotations

from typing import Iterable

from ...models import Bundle, Finding, Recommendation, Severity
from ..base import Rule, register
from ..knowledge import REFS
from ...ingest.config import flatten


def _iter_flat(bundle: Bundle):
    """Yield (config_doc, dotted_key, value) over every JSON-ish config."""

    for doc in bundle.configs:
        if isinstance(doc.data, (dict, list)):
            for key, value in flatten(doc.data).items():
                yield doc, key, value
        elif isinstance(doc.data, dict):  # pragma: no cover - covered above
            for key, value in doc.data.items():
                yield doc, key, value


@register
class TelnetEnabledRule(Rule):
    """Flag plaintext management (telnet) explicitly enabled in config."""

    rule_id = "CFG-TELNET-ENABLED"
    category = "config"

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        for doc, key, value in _iter_flat(bundle):
            kl = key.lower()
            if kl.endswith("telnet.enabled") or kl == "mgmt.telnet":
                if str(value).lower() in ("true", "1", "enabled", "yes"):
                    yield Finding(
                        rule_id=self.rule_id,
                        title="Telnet (plaintext management) is enabled",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        confidence=0.9,
                        description=(
                            "A configuration enables Telnet, which transmits "
                            "credentials and management traffic in plaintext. "
                            "SSH should be used instead."
                        ),
                        evidence=[doc.evidence(key, value)],
                        tags=["security", "config"],
                        recommendations=[
                            Recommendation(
                                summary="Disable Telnet; use SSH for device access.",
                                diagnostic_commands=[
                                    "# Confirm where telnet is enabled:",
                                    f"# config key: {key} = {value}",
                                ],
                                remediation_commands=[
                                    "# Disable device Telnet in UniFi Network UI",
                                    "# (Settings > System > Advanced) and rely on",
                                    "# SSH (Device SSH Authentication).",
                                ],
                                risk="Low; ensure SSH access works before disabling.",
                                reference=REFS["udm_ssh"],
                            ),
                        ],
                    )
                    return  # one finding is enough


@register
class ShortDhcpLeaseRule(Rule):
    """Flag a very short DHCP lease time that can cause churn.

    Fires only on an explicit numeric lease value below a conservative floor,
    so it cannot misfire on a sensible default.
    """

    rule_id = "CFG-DHCP-LEASE-SHORT"
    category = "config"
    FLOOR_SECONDS = 300  # 5 minutes — below this, lease renewals churn

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        for doc, key, value in _iter_flat(bundle):
            kl = key.lower()
            if not (kl.endswith("dhcpd.lease") or kl.endswith("lease_time")
                    or kl.endswith("dhcp_lease")):
                continue
            try:
                seconds = int(value)
            except (TypeError, ValueError):
                continue
            if 0 < seconds < self.FLOOR_SECONDS:
                yield Finding(
                    rule_id=self.rule_id,
                    title=f"Very short DHCP lease time ({seconds}s)",
                    severity=Severity.LOW,
                    category=self.category,
                    confidence=0.8,
                    description=(
                        f"A DHCP lease time of {seconds} seconds is unusually "
                        "short and causes frequent lease renewals and extra "
                        "DHCP traffic. Unless deliberately set for a transient "
                        "network, a longer lease (hours) is typical."
                    ),
                    evidence=[doc.evidence(key, value)],
                    tags=["dhcp", "config"],
                    recommendations=[
                        Recommendation(
                            summary="Raise the lease time unless churn is intended.",
                            remediation_commands=[
                                "# UniFi Network UI: Settings > Networks >",
                                "# (network) > DHCP Lease Time (e.g. 86400).",
                            ],
                            risk="Negligible.",
                            reference=REFS["rfc2131"],
                        ),
                    ],
                )
                return
