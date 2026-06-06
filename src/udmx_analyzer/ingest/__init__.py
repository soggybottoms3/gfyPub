"""Ingestion: turn heterogeneous UniFi artifacts into a normalized Bundle.

The public entry point is :func:`load_paths`, which dispatches each input path
to the right parser based on extension and content sniffing, accumulating
everything into one :class:`~udmx_analyzer.models.Bundle`.
"""

from .loader import load_paths, load_path

__all__ = ["load_paths", "load_path"]
