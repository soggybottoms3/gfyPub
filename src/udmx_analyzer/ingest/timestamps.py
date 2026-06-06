"""Best-effort timestamp parsing for log lines.

UniFi/Linux logs mix several timestamp conventions depending on the source:

* RFC 3164 BSD syslog: ``Jan  2 15:04:05`` (no year)
* RFC 5424 / ISO 8601: ``2026-01-02T15:04:05.123+00:00``
* journald short-iso and epoch forms
* kernel ``[   12.345678]`` monotonic stamps (not wall clock; ignored)

We parse what we can and return ``None`` otherwise. A missing year on BSD
stamps is filled from a reference year (the file's mtime year by default) so
relative ordering and windowing still work.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# 2026-01-02T15:04:05(.123)?(+00:00|Z)?  or with a space separator.
_ISO_RE = re.compile(
    r"(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[T ]"
    r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?P<frac>\.\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?"
)

# BSD syslog: "Jan  2 15:04:05"
_BSD_RE = re.compile(
    r"(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<d>\d{1,2})\s+(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
)


def parse_timestamp(text: str, default_year: Optional[int] = None) -> Optional[datetime]:
    """Extract the first recognizable timestamp from ``text``.

    Returns a naive :class:`datetime` (timezone offset, if present, is dropped
    after normalization is unnecessary for relative correlation). ``None`` when
    no supported format is found.
    """

    m = _ISO_RE.search(text)
    if m:
        try:
            micro = 0
            if m.group("frac"):
                micro = int(round(float(m.group("frac")) * 1_000_000))
            return datetime(
                int(m.group("y")), int(m.group("mo")), int(m.group("d")),
                int(m.group("h")), int(m.group("mi")), int(m.group("s")),
                micro,
            )
        except ValueError:
            return None

    m = _BSD_RE.search(text)
    if m:
        year = default_year or datetime.now().year
        try:
            return datetime(
                year, _MONTHS[m.group("mon")], int(m.group("d")),
                int(m.group("h")), int(m.group("mi")), int(m.group("s")),
            )
        except ValueError:
            return None

    return None
