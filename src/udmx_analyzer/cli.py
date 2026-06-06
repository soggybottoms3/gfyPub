"""Command-line entry point: ``udmx-analyze``.

Usage examples::

    udmx-analyze ./support_file.zip
    udmx-analyze /var/log/syslog config.gateway.json autobackup.unf
    udmx-analyze ./logs_dir --format html --output report.html
    udmx-analyze ./support.zip --format json --min-severity medium
    udmx-analyze ./support.zip --web        # open the local web UI on results
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .analyze import analyze
from .ingest import load_paths
from .models import AnalysisResult, Severity
from .report import render_html, render_json, render_text

_SEVERITY_ARG = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


def _filter_min_severity(result: AnalysisResult, minimum: Severity) -> AnalysisResult:
    result.findings = [f for f in result.findings if f.severity >= minimum]
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="udmx-analyze",
        description=(
            "Ingest and analyze UniFi Dream Machine Pro Max logs, syslogs, "
            "backups (.unf), configs, and support files; report evidence-based "
            "findings and the CLI commands to investigate or fix them."
        ),
    )
    p.add_argument("paths", nargs="*",
                   help="Files or directories to analyze (logs, .unf, .zip, "
                        ".json, support files). Directories are walked.")
    p.add_argument("--format", choices=["text", "json", "html"], default="text",
                   help="Output format (default: text).")
    p.add_argument("--output", "-o", metavar="FILE",
                   help="Write the report to FILE instead of stdout.")
    p.add_argument("--min-severity", choices=list(_SEVERITY_ARG), default="info",
                   help="Only report findings at or above this severity.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI color in text output.")
    p.add_argument("--web", action="store_true",
                   help="Serve an interactive local web UI instead of printing "
                        "(also accepts uploads in the browser).")
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind host for --web (default: 127.0.0.1, local only).")
    p.add_argument("--port", type=int, default=8744,
                   help="Bind port for --web (default: 8744).")
    p.add_argument("--version", action="version",
                   version=f"udmx-analyzer {__version__}")
    return p


def run_analysis(paths: List[str]) -> AnalysisResult:
    bundle = load_paths(paths)
    return analyze(bundle)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.web:
        # Defer import so the core CLI has zero web dependencies.
        from .web.server import serve
        preset = run_analysis(args.paths) if args.paths else None
        serve(host=args.host, port=args.port, preset_result=preset)
        return 0

    if not args.paths:
        build_parser().error("provide at least one path, or use --web")

    result = run_analysis(args.paths)
    _filter_min_severity(result, _SEVERITY_ARG[args.min_severity])

    if args.format == "json":
        rendered = render_json(result)
    elif args.format == "html":
        rendered = render_html(result)
    else:
        color = False if args.no_color else None
        rendered = render_text(result, color=color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"Wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    # Exit code reflects worst severity: 0 clean, 1 low/med, 2 high+, so the
    # tool is usable as a CI/monitoring gate.
    worst = max((f.severity for f in result.findings), default=Severity.INFO)
    if worst >= Severity.HIGH:
        return 2
    if worst >= Severity.LOW:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
