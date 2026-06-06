"""DNS and DHCP rules."""

from __future__ import annotations

import re
from typing import Iterable

from ...models import Bundle, Finding, Recommendation, Severity
from ..base import Rule, register
from .. import knowledge as kb


@register
class DhcpPoolExhaustionRule(Rule):
    """Detect DHCP failures to allocate addresses (pool exhausted)."""

    rule_id = "DHCP-POOL-EXHAUSTION"
    category = "dns_dhcp"
    _RE = re.compile(
        r"(no free leases|pool .* exhausted|DHCPDISCOVER.*no .*available|"
        r"no leases available)", re.IGNORECASE,
    )

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [ev for ev in bundle.log_events if self._RE.search(ev.raw)]
        if not events:
            return

        yield Finding(
            rule_id=self.rule_id,
            title=f"DHCP pool exhaustion ({len(events)} events)",
            severity=Severity.HIGH,
            category=self.category,
            confidence=0.9,
            description=(
                "The DHCP server logged that it had no free leases to hand out. "
                "New clients on the affected network cannot obtain an IP "
                "address. This is caused by a DHCP scope that is too small for "
                "the number of devices, or by a lease time so long that "
                "departed devices keep their reservations."
            ),
            evidence=[ev.evidence() for ev in events[:6]],
            tags=["dhcp", "addressing"],
            recommendations=[
                Recommendation(
                    summary=(
                        "Check current lease utilization, then enlarge the "
                        "scope or shorten the lease time."
                    ),
                    diagnostic_commands=[
                        "ssh root@<udm-ip>",
                        "# Active leases (path varies by firmware):",
                        "cat /data/udapi-config/dnsmasq.lease 2>/dev/null | wc -l",
                        "cat /run/dnsmasq*.leases 2>/dev/null | wc -l",
                    ],
                    remediation_commands=[
                        "# In UniFi Network UI: Settings > Networks > (network):",
                        "#  - widen the DHCP range, or",
                        "#  - reduce 'DHCP Lease Time' (default 86400s) so freed",
                        "#    addresses return to the pool sooner.",
                    ],
                    risk=(
                        "Widening the subnet may require re-addressing; "
                        "shortening lease time slightly increases DHCP traffic. "
                        "Both are low-risk but reconnect clients."
                    ),
                    reference=kb.REFS["rfc2131"],
                ),
            ],
            references=[kb.REFS["rfc2131"]],
        )


@register
class DnsFailureRule(Rule):
    """Detect a volume of DNS resolution failures on the gateway."""

    rule_id = "DNS-RESOLUTION-FAILURES"
    category = "dns_dhcp"
    THRESHOLD = 10
    _RE = re.compile(
        r"(SERVFAIL|REFUSED|no servers could be reached|"
        r"dnsmasq.*(failed|cannot)|resolve.*fail)", re.IGNORECASE,
    )

    def run(self, bundle: Bundle) -> Iterable[Finding]:
        events = [ev for ev in bundle.log_events if self._RE.search(ev.raw)]
        if len(events) < self.THRESHOLD:
            return

        yield Finding(
            rule_id=self.rule_id,
            title=f"Frequent DNS resolution failures ({len(events)} events)",
            severity=Severity.MEDIUM,
            category=self.category,
            confidence=0.7,
            description=(
                f"{len(events)} DNS failure events (SERVFAIL/REFUSED/unreachable "
                "resolver) were logged. Clients will experience this as slow or "
                "broken browsing even when the WAN link is up. The cause is "
                "usually an unreachable or overloaded upstream resolver, or a "
                "misconfigured forwarder."
            ),
            evidence=[ev.evidence() for ev in events[:6]],
            tags=["dns"],
            recommendations=[
                Recommendation(
                    summary="Test resolution against the configured forwarders.",
                    diagnostic_commands=[
                        "ssh root@<udm-ip>",
                        "# Configured upstream resolvers:",
                        "cat /etc/resolv.conf",
                        "# Direct test against each forwarder:",
                        "dig @1.1.1.1 example.com +short",
                        "dig @<configured-resolver> example.com +short",
                        "# Local dnsmasq health:",
                        "dig @127.0.0.1 example.com +short",
                    ],
                    remediation_commands=[
                        "# In UniFi Network UI: Settings > Internet (WAN) or",
                        "# Networks, set reliable upstream DNS servers",
                        "# (e.g. 1.1.1.1 / 9.9.9.9) and avoid pointing clients at",
                        "# a resolver that is itself down.",
                    ],
                    risk=(
                        "Changing DNS affects all clients; validate the new "
                        "resolver responds before rolling it out."
                    ),
                    reference=kb.REFS["rfc1035"],
                ),
            ],
            references=[kb.REFS["rfc1035"]],
        )
