"""Run all rules over a Bundle and correlate the results."""

from __future__ import annotations

from typing import List

from ..models import AnalysisResult, Bundle, Finding
from . import base
from . import rules as _rules  # noqa: F401  (import registers the rules)
from .correlate import correlate

# Exposed for introspection/tests: the populated rule registry.
REGISTRY = base


def analyze(bundle: Bundle) -> AnalysisResult:
    """Execute every registered rule, then correlators, and collect findings.

    A rule that raises is isolated: its failure is recorded as an ingest-style
    warning on the bundle rather than aborting the whole analysis, so one bad
    rule never blinds the rest of the report.
    """

    findings: List[Finding] = []
    for rule in base.all_rules():
        try:
            findings.extend(rule.run(bundle))
        except Exception as exc:  # noqa: BLE001 - resilience over strictness
            bundle.warnings.append(
                f"rule {rule.rule_id} raised {type(exc).__name__}: {exc}"
            )

    findings.extend(correlate(bundle, findings))
    return AnalysisResult(findings=findings, bundle=bundle)
