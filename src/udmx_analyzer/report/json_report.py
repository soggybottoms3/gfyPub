"""JSON report renderer — the machine-readable, scriptable output."""

from __future__ import annotations

import json

from ..models import AnalysisResult


def render_json(result: AnalysisResult, indent: int = 2) -> str:
    return json.dumps(result.as_dict(), indent=indent, default=str)
