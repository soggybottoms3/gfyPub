# udmx-analyzer

Ingest and analyze **UniFi Dream Machine Pro Max** data — logs, syslogs,
encrypted backups (`.unf`), configuration files, and support-file bundles —
then **correlate issues**, make **evidence-based recommendations**, and emit the
**CLI commands** to investigate or fix them.

It runs entirely on your machine. UniFi support files and backups contain
network topology, client lists, and settings; nothing here is uploaded to any
external service.

## Design principle: factual by construction

Every finding must point back at the data that produced it. The core
`Finding` type cannot be constructed without `Evidence` (source file + line or
JSON path + the raw excerpt), so a rule physically cannot report a problem it
did not observe. Recommendations cite the relevant standard (IEEE 802.11, the
RFCs) or UniFi docs, lead with **read-only diagnostics**, and clearly separate
and risk-annotate any **state-changing** command. The tool never claims
firmware is "outdated" from a hardcoded version number — it reports the
installed version and only flags an update when an update notice is actually
present in the logs.

## Install

```bash
# from the repo root
pip install -e .            # core (pure standard library)
pip install -e '.[backup]'  # adds .unf backup decryption (cryptography)
pip install -e '.[dev]'     # adds pytest
```

No install is required to try it: `PYTHONPATH=src python3 -m udmx_analyzer ...`.

## Usage

```bash
# Analyze a support-file bundle
udmx-analyze ./support_file.zip

# Mix sources; directories are walked recursively
udmx-analyze /var/log/syslog config.gateway.json autobackup.unf ./logs_dir

# Machine-readable / shareable reports
udmx-analyze ./support.zip --format json -o report.json
udmx-analyze ./support.zip --format html -o report.html

# Only surface what matters; usable as a CI/monitoring gate (see exit codes)
udmx-analyze ./support.zip --min-severity high

# Interactive local web UI (drag-and-drop uploads, loopback-only)
udmx-analyze --web                 # empty UI to upload into
udmx-analyze ./support.zip --web   # preloads results, also accepts uploads
udmx-web --port 8744               # standalone web entry point
```

**Exit codes** (for scripting): `0` clean, `1` low/medium findings, `2` at
least one high/critical finding.

### Try it on the bundled sample

```bash
PYTHONPATH=src python3 -m udmx_analyzer samples
```

`samples/` contains a synthetic syslog and config that trigger the WAN-flap,
Wi-Fi deauth-storm, DFS-radar, OOM, SSH brute-force, DNS-failure,
adoption-failure, firmware-notice, telnet-enabled, and short-DHCP-lease rules,
plus the WAN↔DNS and OOM↔adoption correlations.

## What it detects

| Area | Rules |
|------|-------|
| WAN | uplink flapping (link up/down storms) |
| Wi-Fi | client deauth/disassoc storms with decoded 802.11 reason codes; DFS radar events |
| System | OOM kills (with victim process), disk-full, thermal warnings |
| Security | SSH/console brute force (grouped by source IP); IDS/IPS alert summary |
| DNS/DHCP | DHCP pool exhaustion; DNS resolution-failure rate |
| Firmware/devices | installed-version inventory; update notices; adoption/connectivity failures |
| Config | telnet enabled; implausibly short DHCP lease |
| Correlation | WAN instability → DNS failures; OOM → device disconnects; disk-full → cascading errors |

Each rule has conservative thresholds (documented inline) to avoid false
positives, and every match is reported with its evidence and remediation.

## Supported inputs

- **Plain logs / syslog** — RFC 3164 (BSD) and RFC 5424, with or without a
  `<PRI>` prefix; `.gz` is decompressed transparently.
- **Support files** — `.zip` or `.tar(.gz)` bundles; members are routed to the
  log or config parser and high-value facts (model, version, devices) are
  harvested.
- **Config files** — JSON (`config.gateway.json`, exports) and UniFi dotted
  key/value (`system.cfg`-style).
- **Backups** — encrypted `.unf` (AES-CBC ZIP). See the note below.

### `.unf` backup key

`.unf` files are AES-CBC encrypted with a *static* (non-secret) key/IV. The
exact bytes are reported inconsistently across firmware generations and this
build was assembled without a sample `.unf` to verify against, so it does **not**
ship a hardcoded key asserted as fact. Supply it via environment variables:

```bash
export UDMX_BACKUP_KEY=<hex>   # must decode to 16/24/32 bytes (AES)
export UDMX_BACKUP_IV=<hex>    # optional; defaults to the common value
udmx-analyze autobackup.unf
```

If the key is missing or wrong, you get a clear, actionable warning — never a
crash or a silently-wrong result.

## Architecture

```
ingest/   → normalize everything into one Bundle (logs, configs, devices, facts)
analyze/  → deterministic, evidence-bound rules + cross-source correlation
report/   → text (TTY color), JSON (scriptable), HTML (self-contained)
web/      → loopback http.server UI over the same engine (stdlib only)
cli.py    → argument handling, severity filtering, exit codes
```

`Bundle` is the single source-agnostic view rules read from; they never touch
raw files. New detectors are a small `Rule` subclass decorated with
`@register` — see `src/udmx_analyzer/analyze/rules/` and the conventions in
`CLAUDE.md`.

## Tests

```bash
pytest         # unit tests for parsing, rules, correlation, reports, web, backup
```

## Safety notes

- Recommendations show read-only diagnostics first; anything that changes
  device state is labeled with its risk. Verify interface names, file paths,
  and region-specific values (e.g. allowed Wi-Fi channels) for your firmware
  before running remediation commands.
- The web UI binds to `127.0.0.1` by default and warns if you bind elsewhere.
  Uploaded files are processed in a temp directory and deleted immediately.
