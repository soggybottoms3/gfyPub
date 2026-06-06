"""Report renderers for an AnalysisResult."""

from .text import render_text
from .json_report import render_json
from .html import render_html

__all__ = ["render_text", "render_json", "render_html"]
