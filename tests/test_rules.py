"""Tests that rules fire (and only fire) on the right evidence."""

import os

import pytest

from udmx_analyzer.analyze import analyze
from udmx_analyzer.ingest import load_paths
from udmx_analyzer.ingest.syslog import parse_text
from udmx_analyzer.models import Bundle, Finding, Severity

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def _analyze_text(text: str):
    b = Bundle()
    b.log_events = parse_text(text, "test", 2026)
    return analyze(b)


def test_finding_requires_evidence():
    with pytest.raises(ValueError):
        Finding(
            rule_id="X", title="t", severity=Severity.LOW,
            category="c", description="d", evidence=[],
        )


def test_sample_triggers_expected_rules():
    result = analyze(load_paths([SAMPLES]))
    ids = {f.rule_id for f in result.findings}
    # Core detectors should all fire on the crafted sample.
    for expected in [
        "WAN-FLAP", "WIFI-DEAUTH-STORM", "WIFI-DFS-RADAR", "SYS-OOM",
        "SEC-AUTH-BRUTEFORCE", "DNS-RESOLUTION-FAILURES",
        "DEV-ADOPTION-FAILURE", "FW-UPDATE-AVAILABLE",
        "CFG-TELNET-ENABLED", "CFG-DHCP-LEASE-SHORT",
    ]:
        assert expected in ids, f"expected {expected} in {sorted(ids)}"


def test_correlation_links_wan_and_dns():
    result = analyze(load_paths([SAMPLES]))
    ids = {f.rule_id for f in result.findings}
    assert "CORR-WAN-DNS" in ids
    corr = next(f for f in result.findings if f.rule_id == "CORR-WAN-DNS")
    assert corr.evidence  # inherits evidence from the linked findings


def test_clean_logs_produce_no_findings():
    text = "\n".join(
        f"<30>Jan  2 03:0{i}:00 UDMPRO systemd[1]: nominal heartbeat {i}"
        for i in range(9)
    )
    result = _analyze_text(text)
    actionable = [f for f in result.findings if f.severity >= Severity.LOW]
    assert actionable == [], f"unexpected findings: {[f.rule_id for f in actionable]}"


def test_wan_flap_below_threshold_silent():
    text = "\n".join([
        "<29>Jan  2 03:15:11 UDMPRO kernel: eth4: NIC Link is Down",
        "<30>Jan  2 03:15:13 UDMPRO kernel: eth4: NIC Link is Up",
    ])
    result = _analyze_text(text)
    assert "WAN-FLAP" not in {f.rule_id for f in result.findings}


def test_deauth_reason_codes_decoded():
    result = analyze(load_paths([SAMPLES]))
    f = next(f for f in result.findings if f.rule_id == "WIFI-DEAUTH-STORM")
    # Reason 4 (inactivity) and 15 (4-way handshake timeout) appear in sample.
    assert "Inactivity".lower() in f.description.lower()
    assert "4-Way Handshake" in f.description
