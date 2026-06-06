# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`udmx-analyzer` ingests UniFi Dream Machine Pro Max artifacts (syslog, support
files, encrypted `.unf` backups, configs) into one normalized model, runs
deterministic diagnostic rules, correlates findings across sources, and renders
reports + the CLI commands to investigate/fix issues. It is local-first (the
data is sensitive) and has no required third-party dependencies — only the
standard library, plus optional `cryptography` for `.unf` decryption.

## Commands

```bash
# Run (no install needed)
PYTHONPATH=src python3 -m udmx_analyzer samples
PYTHONPATH=src python3 -m udmx_analyzer <paths...> --format {text|json|html} [-o FILE]
PYTHONPATH=src python3 -m udmx_analyzer --web --port 8744   # local web UI

# Installed entry points (after `pip install -e .`)
udmx-analyze <paths...>
udmx-web

# Tests
pip install pytest         # not declared as a hard dep; install for dev
pytest                     # whole suite
pytest tests/test_rules.py::test_sample_triggers_expected_rules   # one test
pytest -k correlate        # by keyword
```

Optional extras: `pip install -e '.[backup]'` (cryptography), `'.[dev]'` (pytest).

CLI exit codes are meaningful: `0` clean, `1` low/medium, `2` high/critical —
so the tool can gate CI/monitoring.

## Architecture (the big picture)

The pipeline is **ingest → analyze → report**, and the contract between stages
is two types in `src/udmx_analyzer/models.py`:

- **`Bundle`** — the single source-agnostic view of everything ingested
  (`log_events`, `configs`, `devices`, `system_info`, `warnings`). Rules read
  *only* from this; they never touch raw files. All parsers in `ingest/`
  converge here via `ingest/loader.py:load_paths`, which dispatches each path
  by extension/content sniffing (dir-walk, `.unf`, archive, `.gz`, config, log).
- **`Finding`** — requires non-empty `Evidence` in `__post_init__`. This is the
  load-bearing invariant that keeps the tool factual: **a rule cannot emit a
  finding it has no evidence for.** Preserve this when adding rules.

`analyze/engine.py:analyze` instantiates every registered rule, runs each in a
try/except (a raising rule becomes a bundle warning, never aborts the run),
then runs `analyze/correlate.py` to link findings into root-cause/symptom
relationships (e.g. WAN-flap → DNS-failures). Reports in `report/` all consume
the same `AnalysisResult`. The `web/` server is stdlib `http.server` over the
identical engine — no framework, loopback by default.

## Adding a rule

1. Subclass `Rule` (`analyze/base.py`) in a module under `analyze/rules/`, set a
   unique `rule_id` and `category`, implement `run(bundle) -> Iterable[Finding]`.
2. Decorate with `@register`. Import the module in `analyze/rules/__init__.py`
   so registration happens.
3. Emit `Finding`s with real `Evidence` (use `LogEvent.evidence()` /
   `ConfigDoc.evidence(path, value)`). Put facts/thresholds in
   `analyze/knowledge.py` and cite them.
4. Add a triggering case to `samples/` and assert it in `tests/test_rules.py`.

## Conventions that matter here

- **Evidence-bound, deterministic, side-effect-free rules.** No network, no
  guessing about the user's environment, same input → same output.
- **Recommendations lead with read-only diagnostics**; state-changing commands
  go in `remediation_commands` with a `risk` note. Device-specific values
  (interface names like `eth4`, paths under `/data`, allowed Wi-Fi channels)
  are placeholders the user must verify — never assert them as universal.
- **Never hardcode a "latest firmware" version** to call something outdated;
  report the observed version and only flag updates the logs announce.
- **`.unf` key is not hardcoded as fact.** Decryption reads `UDMX_BACKUP_KEY` /
  `UDMX_BACKUP_IV` (hex), validates AES key length, and warns instead of
  crashing or producing silently-wrong output. See `ingest/backup.py`.
- Thresholds (flap counts, error rates) live as class constants with an inline
  rationale; keep them conservative to avoid false positives.

## Environment note

The dev container's system `cryptography` wheel lacks `_cffi_backend`, so real
AES panics there; the backup round-trip test skips via
`pytest.importorskip("_cffi_backend")`. This is environmental, not a code bug.
