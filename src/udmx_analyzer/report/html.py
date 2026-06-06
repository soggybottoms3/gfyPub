"""Self-contained HTML report renderer.

Produces a single static HTML string with inline CSS — no external assets, no
network — so it is safe to open from anywhere or hand to a colleague. Also
reused by the web UI to render results in the browser.
"""

from __future__ import annotations

from html import escape
from typing import List

from ..models import AnalysisResult, Finding, Severity

_SEV_CLASS = {
    Severity.CRITICAL: "crit",
    Severity.HIGH: "high",
    Severity.MEDIUM: "med",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

_CSS = """
:root{--bg:#0f1115;--card:#1a1d24;--fg:#e6e6e6;--muted:#9aa0aa;--line:#2a2e38;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
 font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px} .sub{color:var(--muted);margin-bottom:16px}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0 24px}
.pill{padding:4px 10px;border-radius:999px;font-weight:600;font-size:12px}
.crit{background:#7f1d1d;color:#fff}.high{background:#b91c1c;color:#fff}
.med{background:#a16207;color:#fff}.low{background:#0e7490;color:#fff}
.info{background:#374151;color:#cbd5e1}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
 padding:16px;margin:0 0 16px}
.card h3{margin:0 0 6px;font-size:16px}
.tag{display:inline-block;border:1px solid var(--line);border-radius:6px;
 padding:1px 6px;color:var(--muted);font-size:11px;margin-left:6px}
.meta{color:var(--muted);font-size:12px;margin:2px 0 10px}
.desc{white-space:pre-wrap;margin:8px 0}
.section{margin-top:10px}
.label{font-weight:600;color:var(--muted);text-transform:uppercase;
 font-size:11px;letter-spacing:.04em}
pre{background:#0b0d12;border:1px solid var(--line);border-radius:8px;
 padding:10px;overflow:auto;margin:6px 0}
.ev{border-left:3px solid var(--line);padding:6px 10px;margin:6px 0;
 background:#0b0d12;border-radius:0 8px 8px 0}
.ev .src{color:var(--muted);font-size:12px}
.ev code{color:#e6e6e6}
.diag pre{border-color:#0e7490}.remed pre{border-color:#a16207}
.risk{color:#fca5a5;margin:6px 0}
.warn{color:#fbbf24}
footer{color:var(--muted);font-size:12px;margin-top:24px}
"""


def _evidence_html(f: Finding) -> str:
    rows = []
    for e in f.evidence:
        ts = f" @ {escape(e.timestamp.isoformat())}" if e.timestamp else ""
        rows.append(
            f'<div class="ev"><div class="src">{escape(e.source)} '
            f'({escape(e.locator)}){ts}</div>'
            f'<code>{escape(e.excerpt)}</code></div>'
        )
    return "".join(rows)


def _commands_html(title: str, cls: str, cmds: List[str]) -> str:
    if not cmds:
        return ""
    body = escape("\n".join(cmds))
    return (
        f'<div class="section {cls}"><div class="label">{escape(title)}</div>'
        f"<pre>{body}</pre></div>"
    )


def _finding_html(idx: int, f: Finding) -> str:
    cls = _SEV_CLASS[f.severity]
    tags = "".join(f'<span class="tag">{escape(t)}</span>' for t in f.tags)
    recs = []
    for r in f.recommendations:
        recs.append(f'<div class="section"><div class="label">Recommendation</div>'
                    f"<div>{escape(r.summary)}</div></div>")
        recs.append(_commands_html("Diagnostics (read-only)", "diag",
                                   r.diagnostic_commands))
        recs.append(_commands_html("Remediation (changes state)", "remed",
                                   r.remediation_commands))
        if r.risk:
            recs.append(f'<div class="risk">⚠ Risk: {escape(r.risk)}</div>')
        if r.reference:
            recs.append(f'<div class="meta">Ref: {escape(r.reference)}</div>')
    refs = ""
    if f.references:
        refs = (f'<div class="meta">References: '
                f'{escape("; ".join(f.references))}</div>')

    return f"""
    <div class="card">
      <h3><span class="pill {cls}">{escape(f.severity.label)}</span>
        {idx}. {escape(f.title)}{tags}</h3>
      <div class="meta">{escape(f.rule_id)} · confidence {f.confidence:.0%}
        · {escape(f.category)}</div>
      <div class="desc">{escape(f.description)}</div>
      <div class="section"><div class="label">Evidence</div>
        {_evidence_html(f)}</div>
      {''.join(recs)}
      {refs}
    </div>
    """


def render_html(result: AnalysisResult) -> str:
    b = result.bundle
    counts = result.counts_by_severity()
    pills = "".join(
        f'<span class="pill {_SEV_CLASS[s]}">{s.label}: {counts[s.label]}</span>'
        for s in sorted(Severity, reverse=True)
    )

    src_list = ""
    if b:
        src_list = "".join(f"<li>{escape(s)}</li>" for s in b.sources)

    warnings = ""
    if b and b.warnings:
        items = "".join(f"<li>{escape(w)}</li>" for w in b.warnings)
        warnings = (f'<div class="card"><div class="label warn">Ingest warnings'
                    f"</div><ul>{items}</ul></div>")

    findings = result.sorted_findings()
    if findings:
        body = "".join(_finding_html(i, f) for i, f in enumerate(findings, 1))
    else:
        body = ('<div class="card">No issues detected in the supplied data.'
                "</div>")

    dev = ""
    if b and (b.system_info.get("model") or b.system_info.get("version")):
        dev = (f"Device: model={escape(str(b.system_info.get('model')))} · "
               f"version={escape(str(b.system_info.get('version')))}")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UDM Pro Max Analysis Report</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<h1>UniFi Dream Machine Pro Max — Analysis Report</h1>
<div class="sub">Generated {escape(result.generated_at.isoformat(timespec='seconds'))}
 · {len(b.log_events) if b else 0} log events · {dev}</div>
<div class="pills">{pills}</div>
<div class="card"><div class="label">Sources</div><ul>{src_list}</ul></div>
{warnings}
{body}
<footer>Findings are evidence-based: each cites the source data that triggered
 it. Read-only diagnostics are listed before any state-changing command. Verify
 interface names, paths, and region-specific values for your firmware before
 running remediation.</footer>
</div></body></html>"""
