"""Parse UniFi "support file" / diagnostics bundles.

A UniFi support file (downloaded from the console UI, or generated on-device)
is an archive — ZIP or tar/tar.gz — containing a tree of diagnostics:

* ``*.log`` / ``messages`` / ``syslog`` — system and application logs
* ``*.json`` — device lists, site settings, health/stat snapshots, sysinfo
* ``system.properties`` / ``*.cfg`` — controller and device config
* assorted text reports (``ifconfig``, ``ip_route``, ``dmesg`` captures)

This parser walks the archive members, routes each to the syslog or config
parser by name/content, and harvests a few high-value facts (model, firmware
version, uptime, resource stats) into ``system_info`` when present in obvious
JSON shapes (``sysinfo``, ``device``...). It is intentionally tolerant:
anything unrecognized that looks like text is still parsed as a log so its
lines remain searchable.
"""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from ..models import ConfigDoc, DeviceInfo, LogEvent
from . import syslog as syslog_parser
from .config import parse_config

_LOG_HINTS = ("log", "messages", "syslog", "dmesg", "journal")
_CONFIG_HINTS = (".json", ".properties", ".cfg", ".cconfig")


def _looks_like_log(name: str) -> bool:
    lname = name.lower()
    return lname.endswith(".log") or any(h in lname for h in _LOG_HINTS)


def _iter_archive(raw: bytes, source: str):
    """Yield ``(member_name, bytes)`` for ZIP or tar archives."""

    if raw[:2] == b"PK":
        zf = zipfile.ZipFile(io.BytesIO(raw))
        for member in zf.namelist():
            if member.endswith("/"):
                continue
            yield member, zf.read(member)
        return

    # tar / tar.gz / tar.bz2 — let tarfile sniff compression.
    bio = io.BytesIO(raw)
    try:
        tf = tarfile.open(fileobj=bio, mode="r:*")
    except tarfile.TarError as exc:
        raise ValueError(f"{source}: not a recognized ZIP or tar archive: {exc}")
    for member in tf.getmembers():
        if not member.isfile():
            continue
        f = tf.extractfile(member)
        if f is None:
            continue
        yield member.name, f.read()


def parse_support_file(
    raw: bytes, source: str, default_year: Optional[int] = None
) -> Tuple[List[LogEvent], List[ConfigDoc], List[DeviceInfo], Dict[str, Any], List[str]]:
    """Return ``(events, configs, devices, system_info, warnings)``."""

    events: List[LogEvent] = []
    configs: List[ConfigDoc] = []
    devices: List[DeviceInfo] = []
    system_info: Dict[str, Any] = {}
    warnings: List[str] = []

    for member, payload in _iter_archive(raw, source):
        msrc = f"{source}:{member}"
        lname = member.lower()

        # Decode text once; skip clearly-binary members.
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            if lname.endswith(_CONFIG_HINTS) or _looks_like_log(member):
                text = payload.decode("utf-8", errors="replace")
                warnings.append(f"{msrc}: contained invalid UTF-8 (replaced).")
            else:
                continue  # genuine binary, not useful as text

        if lname.endswith(_CONFIG_HINTS):
            doc = parse_config(text, name=member, source=msrc)
            if doc is not None:
                configs.append(doc)
                _harvest_facts(doc, devices, system_info)
                continue
            # JSON that failed to parse but is named .json: fall through to log.

        if _looks_like_log(member):
            events.extend(syslog_parser.parse_text(text, msrc, default_year))
            continue

        # Unknown text member: keep it searchable as a log.
        events.extend(syslog_parser.parse_text(text, msrc, default_year))

    return events, configs, devices, system_info, warnings


# --- fact harvesting -------------------------------------------------------

_VERSION_KEYS = ("version", "displayable_version", "fw_version")
_MODEL_KEYS = ("model", "model_display", "hw_caps_model")
_UPTIME_KEYS = ("uptime", "uptime_seconds")


def _harvest_facts(
    doc: ConfigDoc, devices: List[DeviceInfo], system_info: Dict[str, Any]
) -> None:
    """Pull well-known fields out of JSON config docs.

    Conservative on purpose: only reads keys whose meaning is unambiguous in
    UniFi's schema, and records the source so it remains traceable evidence.
    """

    data = doc.data
    candidates: List[dict] = []
    if isinstance(data, dict):
        # Common envelope: {"data": [ ... ]}
        inner = data.get("data")
        if isinstance(inner, list):
            candidates.extend(d for d in inner if isinstance(d, dict))
        else:
            candidates.append(data)
    elif isinstance(data, list):
        candidates.extend(d for d in data if isinstance(d, dict))

    for obj in candidates:
        if "mac" in obj and ("model" in obj or "type" in obj):
            devices.append(
                DeviceInfo(
                    name=obj.get("name") or obj.get("hostname"),
                    model=_first(obj, _MODEL_KEYS),
                    mac=obj.get("mac"),
                    ip=obj.get("ip"),
                    version=_first(obj, _VERSION_KEYS),
                    adopted=obj.get("adopted"),
                    state=_state_text(obj.get("state")),
                    extra={"_source": doc.source},
                )
            )
        # Host/controller sysinfo block.
        if any(k in obj for k in ("hostname", "device_type")) and (
            _first(obj, _VERSION_KEYS) or _first(obj, _MODEL_KEYS)
        ):
            system_info.setdefault("model", _first(obj, _MODEL_KEYS))
            system_info.setdefault("version", _first(obj, _VERSION_KEYS))
            system_info.setdefault("uptime", _first(obj, _UPTIME_KEYS))
            system_info.setdefault("hostname", obj.get("hostname"))
            system_info.setdefault("_source", doc.source)


def _first(obj: dict, keys) -> Optional[Any]:
    for k in keys:
        if obj.get(k) not in (None, ""):
            return obj[k]
    return None


def _state_text(state: Any) -> Optional[str]:
    # UniFi numeric device state codes (Network app convention).
    mapping = {
        0: "disconnected", 1: "connected", 2: "pending-adoption",
        4: "upgrading", 5: "provisioning", 6: "heartbeat-missed",
        7: "adopting", 9: "adoption-failed", 11: "isolated",
    }
    if isinstance(state, int):
        return mapping.get(state, str(state))
    if isinstance(state, str):
        return state
    return None
