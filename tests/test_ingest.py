"""Tests for parsing/ingestion."""

import os

from udmx_analyzer.ingest import load_paths
from udmx_analyzer.ingest.config import flatten, parse_config
from udmx_analyzer.ingest.syslog import parse_line, parse_text
from udmx_analyzer.ingest.timestamps import parse_timestamp

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def test_parse_rfc3164_line():
    ev = parse_line(
        "<29>Jan  2 03:15:11 UDMPRO kernel: eth4: NIC Link is Down",
        "x", 1, default_year=2026,
    )
    assert ev is not None
    assert ev.host == "UDMPRO"
    assert ev.process == "kernel"
    assert ev.timestamp is not None
    assert ev.timestamp.month == 1 and ev.timestamp.day == 2
    assert "NIC Link is Down" in ev.message


def test_parse_rfc5424_line():
    line = "<30>1 2026-01-02T15:04:05.123Z UDMPRO unifi 1234 - - adopt ok"
    ev = parse_line(line, "x", 1)
    assert ev is not None
    assert ev.process == "unifi"
    assert ev.timestamp.year == 2026
    assert ev.message.endswith("adopt ok")


def test_blank_line_skipped():
    assert parse_line("   ", "x", 1) is None


def test_iso_and_bsd_timestamps():
    assert parse_timestamp("2026-01-02T15:04:05Z").year == 2026
    bsd = parse_timestamp("Jan  2 15:04:05", default_year=2025)
    assert bsd.year == 2025 and bsd.month == 1


def test_config_flatten_paths():
    flat = flatten({"a": {"b": [1, 2]}, "c": True})
    assert flat["a.b.0"] == 1
    assert flat["a.b.1"] == 2
    assert flat["c"] is True


def test_parse_keyvalue_config():
    doc = parse_config("mgmt.telnet=true\n# comment\nfoo.bar=5", "system.cfg", "s")
    assert doc.data["mgmt.telnet"] == "true"
    assert doc.data["foo.bar"] == "5"


def test_load_sample_directory():
    bundle = load_paths([SAMPLES])
    assert bundle.log_events, "expected parsed log events from sample"
    # The JSON sample should be parsed as a config, not as logs.
    assert any(c.name.endswith(".json") for c in bundle.configs)
    # Events should be time-sorted (dated events ascending).
    dated = [e.timestamp for e in bundle.log_events if e.timestamp]
    assert dated == sorted(dated)
