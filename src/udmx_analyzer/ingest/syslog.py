"""Parse syslog / plain log text into :class:`LogEvent` records.

Handles the two formats UniFi devices emit in practice:

* RFC 3164 BSD style, optionally with a leading ``<PRI>`` priority value::

      <30>Jan  2 15:04:05 UDMPRO kernel: WAN link down on eth4

* RFC 5424 structured style::

      <30>1 2026-01-02T15:04:05.123Z UDMPRO unifi 1234 - - adopt failed

Anything that does not match a known header is still captured as a
``LogEvent`` with ``raw`` preserved, so rules that regex over raw text never
lose a line.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional

from ..models import LogEvent
from .timestamps import parse_timestamp

# <PRI> optionally present. Capture it so we can derive severity if needed.
_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<rest>.*)$", re.DOTALL)

# RFC5424: VERSION TIMESTAMP HOST APP PROCID MSGID ...
_RFC5424_RE = re.compile(
    r"^(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$",
    re.DOTALL,
)

# RFC3164: "Mon  d HH:MM:SS host process[pid]: message"
_RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<rest>.*)$",
    re.DOTALL,
)

# syslog severity from PRI = facility*8 + severity
_SEVERITY_NAMES = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
]


def _severity_from_pri(pri: Optional[str]) -> Optional[str]:
    if pri is None:
        return None
    try:
        return _SEVERITY_NAMES[int(pri) % 8]
    except (ValueError, IndexError):
        return None


def parse_line(raw: str, source: str, line_no: int,
               default_year: Optional[int] = None) -> Optional[LogEvent]:
    """Parse a single line. Returns ``None`` for blank lines."""

    if not raw.strip():
        return None

    body = raw.rstrip("\n")
    severity_text = None

    m = _PRI_RE.match(body)
    if m:
        severity_text = _severity_from_pri(m.group("pri"))
        body = m.group("rest")

    # RFC 5424 (starts with a single-digit version).
    m = _RFC5424_RE.match(body)
    if m:
        return LogEvent(
            raw=raw, source=source, line_no=line_no,
            timestamp=parse_timestamp(m.group("ts"), default_year),
            host=_none_dash(m.group("host")),
            process=_none_dash(m.group("app")),
            severity_text=severity_text,
            message=m.group("rest").strip(),
        )

    # RFC 3164 BSD.
    m = _RFC3164_RE.match(body)
    if m:
        return LogEvent(
            raw=raw, source=source, line_no=line_no,
            timestamp=parse_timestamp(m.group("ts"), default_year),
            host=m.group("host"),
            process=m.group("proc").strip(),
            severity_text=severity_text,
            message=m.group("rest").strip(),
        )

    # Fallback: keep the line, try to find any timestamp in it.
    return LogEvent(
        raw=raw, source=source, line_no=line_no,
        timestamp=parse_timestamp(body, default_year),
        severity_text=severity_text,
        message=body.strip(),
    )


def _none_dash(value: str) -> Optional[str]:
    return None if value == "-" else value


def parse_text(text: str, source: str,
               default_year: Optional[int] = None) -> List[LogEvent]:
    """Parse a whole log blob into events, preserving 1-based line numbers."""

    events: List[LogEvent] = []
    for i, line in enumerate(text.splitlines(), start=1):
        ev = parse_line(line, source, i, default_year)
        if ev is not None:
            events.append(ev)
    return events


def parse_lines(lines: Iterable[str], source: str,
                default_year: Optional[int] = None) -> List[LogEvent]:
    events: List[LogEvent] = []
    for i, line in enumerate(lines, start=1):
        ev = parse_line(line, source, i, default_year)
        if ev is not None:
            events.append(ev)
    return events
