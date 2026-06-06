"""udmx_analyzer — evidence-based analyzer for UniFi Dream Machine Pro Max data.

The package ingests heterogeneous UniFi artifacts (syslog, support files,
encrypted backups, configuration files, plain logs) into a single normalized
:class:`~udmx_analyzer.models.Bundle`, runs a set of deterministic diagnostic
rules over it, correlates findings across sources, and renders reports plus
the CLI commands needed to investigate or remediate.

Design rule: a rule may only emit a :class:`~udmx_analyzer.models.Finding`
that is backed by concrete :class:`~udmx_analyzer.models.Evidence`. Nothing is
inferred from assumptions about the user's environment.
"""

from .models import (
    Bundle,
    Evidence,
    Finding,
    Recommendation,
    Severity,
    AnalysisResult,
)

__version__ = "0.1.0"

__all__ = [
    "Bundle",
    "Evidence",
    "Finding",
    "Recommendation",
    "Severity",
    "AnalysisResult",
    "__version__",
]
