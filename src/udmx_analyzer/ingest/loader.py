"""Dispatch input paths to the right parser and accumulate a Bundle.

Routing is by extension first, then content sniffing:

* directory                -> recurse into every file
* ``.unf``                 -> backup decryptor
* ``.zip`` / ``.tar(.gz)`` -> support-file archive walker
* ``.gz`` (single)         -> gunzip, then re-dispatch by inner name
* ``.json`` / ``.cfg`` / ``.properties`` -> config parser
* ``.log`` / ``.txt`` / others that look textual -> syslog/plain parser

Unreadable or unrecognized inputs are recorded in ``bundle.warnings`` and
never abort the run.
"""

from __future__ import annotations

import gzip
import os
from datetime import datetime
from typing import Iterable, List

from ..models import Bundle
from . import syslog as syslog_parser
from .backup import read_backup
from .config import parse_config
from .support_file import parse_support_file

_ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2")
_CONFIG_EXTS = (".json", ".cfg", ".cconfig", ".properties")
_LOG_EXTS = (".log", ".txt", ".syslog", ".messages", "")


def _year_of(path: str) -> int:
    try:
        return datetime.fromtimestamp(os.path.getmtime(path)).year
    except OSError:
        return datetime.now().year


def load_path(path: str, bundle: Bundle) -> None:
    """Ingest a single file or directory into ``bundle`` in place."""

    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for fname in sorted(files):
                load_path(os.path.join(root, fname), bundle)
        return

    if not os.path.isfile(path):
        bundle.warnings.append(f"{path}: not a file or directory; skipped.")
        return

    bundle.add_source(path)
    lname = path.lower()
    year = _year_of(path)

    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        bundle.warnings.append(f"{path}: cannot read ({exc}); skipped.")
        return

    # Encrypted UniFi backup.
    if lname.endswith(".unf"):
        configs, warns = read_backup(raw, path)
        bundle.configs.extend(configs)
        bundle.warnings.extend(warns)
        return

    # Archives / support files.
    if lname.endswith(_ARCHIVE_EXTS) or raw[:2] == b"PK":
        try:
            events, configs, devices, sysinfo, warns = parse_support_file(
                raw, path, year
            )
        except ValueError as exc:
            bundle.warnings.append(str(exc))
            return
        bundle.log_events.extend(events)
        bundle.configs.extend(configs)
        bundle.devices.extend(devices)
        for k, v in sysinfo.items():
            bundle.system_info.setdefault(k, v)
        bundle.warnings.extend(warns)
        return

    # Single gzipped file: gunzip and re-dispatch by inner name.
    if lname.endswith(".gz"):
        try:
            raw = gzip.decompress(raw)
        except OSError as exc:
            bundle.warnings.append(f"{path}: bad gzip ({exc}); skipped.")
            return
        lname = lname[:-3]

    # Decode text.
    text = raw.decode("utf-8", errors="replace")

    if lname.endswith(_CONFIG_EXTS):
        doc = parse_config(text, name=os.path.basename(path), source=path)
        if doc is not None:
            bundle.configs.append(doc)
            return
        # Named like config but unparseable -> fall through to log capture.

    # Everything else: treat as log text.
    bundle.log_events.extend(syslog_parser.parse_text(text, path, year))


def load_paths(paths: Iterable[str]) -> Bundle:
    """Ingest several inputs into one :class:`Bundle`."""

    bundle = Bundle()
    for p in paths:
        load_path(p, bundle)
    # Keep events globally ordered by time when timestamps exist; undated
    # events retain their original relative order at the end.
    bundle.log_events.sort(
        key=lambda e: (e.timestamp is None, e.timestamp or datetime.min)
    )
    return bundle
