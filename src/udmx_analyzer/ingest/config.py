"""Parse UniFi configuration documents.

Two shapes occur in the wild:

* JSON — ``config.gateway.json``, exported network/site settings, device
  ``cfgversion`` blobs, the Network application's Mongo exports.
* Key/value — UniFi device ``system.cfg`` / ``mgmt`` style files that use
  dotted keys::

      mgmt.is_default=false
      gui.network.lan.dhcpd.lease=86400

Key/value files are parsed into a flat dict keyed by the dotted path, which is
exactly the locator rules cite as evidence.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from ..models import ConfigDoc


def parse_keyvalue(text: str, name: str, source: str) -> ConfigDoc:
    data: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key.strip()] = value.strip()
    return ConfigDoc(name=name, source=source, data=data)


def parse_json(text: str, name: str, source: str) -> Optional[ConfigDoc]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return ConfigDoc(name=name, source=source, data=data)


def parse_config(text: str, name: str, source: str) -> Optional[ConfigDoc]:
    """Sniff JSON vs key/value and parse accordingly."""

    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        doc = parse_json(text, name, source)
        if doc is not None:
            return doc
    if "=" in text:
        return parse_keyvalue(text, name, source)
    return None


def flatten(data: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten nested JSON into dotted paths for evidence locators.

    Lists are indexed (``foo.0.bar``). Scalar leaves are kept as-is.
    """

    out: Dict[str, Any] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.update(flatten(v, key))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            key = f"{prefix}.{i}" if prefix else str(i)
            out.update(flatten(v, key))
    else:
        out[prefix] = data
    return out
