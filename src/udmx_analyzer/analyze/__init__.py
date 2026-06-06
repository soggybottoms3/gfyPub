"""Analysis: deterministic rules over a Bundle, plus cross-source correlation.

:func:`analyze` is the entry point — it runs every registered rule, then the
correlators, and returns an :class:`~udmx_analyzer.models.AnalysisResult`.
"""

from .engine import analyze, REGISTRY

__all__ = ["analyze", "REGISTRY"]
