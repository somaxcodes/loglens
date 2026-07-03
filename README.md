# LogLens

A Python-based Linux log analyzer that parses syslog files, detects errors and warnings, surfaces patterns and noisy services, and optionally redacts PII before sharing logs.

## Features

- Parses standard Linux syslog (traditional and ISO 8601 timestamp formats)
- Detects issues by keyword: `error`, `warning`, `critical`, `failed`, `fatal`, `panic`, `timeout`, `denied`, `refused`, `exception`, `abort`
- Color-coded output with per-keyword highlighting in each issue row
- Severity breakdown: CRITICAL / ERROR / WARNING / UNKNOWN
- Top repeated patterns ranked by frequency
- Issues grouped by service to surface the noisiest sources
- Summary statistics: first/last issue, duration, issues/hour, peak hour
- PII redaction (`--redact`): replaces IPs, emails, phone numbers, and user IDs with `[REDACTED:TYPE]` tokens
- Truncation with `--limit N` for large logs (default 50, `--limit 0` for all)
- `--no-color` for CI pipelines and plain-text output

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic analysis
python3 cli.py --file samples/sample1_syslog.log

# Redact PII before analysis
python3 cli.py --file samples/sample1_syslog.log --redact

# Redact and save a clean copy
python3 cli.py --file samples/sample1_syslog.log --redact --export redacted.log

# Show all issues (no truncation)
python3 cli.py --file samples/sample1_syslog.log --limit 0

# Plain text output (CI-friendly)
python3 cli.py --file samples/sample1_syslog.log --no-color

# Custom PII patterns via JSON config
python3 cli.py --file samples/sample1_syslog.log --redact --config loglens_config.json
```

## Flags

| Flag | Description |
|------|-------------|
| `--file PATH` | Path to the log file (required) |
| `--redact` | Redact PII before analysis |
| `--export PATH` | Save redacted log to file (requires `--redact`) |
| `--config PATH` | JSON file with custom PII patterns (requires `--redact`) |
| `--limit N` | Max issues shown (default 50, 0 = no limit) |
| `--no-color` | Disable color output |

## Sample Output

```
PII Summary — 41 items redacted across all log lines (issue + non-issue)
 Type     Redacted
 IP            24
 EMAIL          9
 PHONE          5
 USERID         3
 TOTAL         41

Issues Found in sample1_syslog.log
 #   Keyword   Log Line
 1   panic     ... kernel: Command line: ... panic=-1 ...
 2   denied    ... sh[105]: Permission denied
 3   failed    ... kernel: Failed to register legacy timer interrupt
...
Total: 78 issues found

Severity Breakdown
 CRITICAL   ERROR   WARNING   UNKNOWN
     0        21       52         5

Summary Statistics
 First issue    2026-05-28 15:47:10
 Last issue     2026-05-28 17:14:25
 Duration       1h 27m
 Issues/hour    53.7
 Peak hour      15:00–16:00 (21 issues)

Top Patterns in sample1_syslog.log
 Rank   Count   Pattern
    1      33   WARNING Daemon: could not connect to Windows Agent...
    2       6   WSL (270) ERROR: CheckConnection: getaddrinfo() failed: -5
...

Issues by Service
 Service              Issue Count
 wsl-pro-service               47
 kernel                        21
```

## PII Redaction Details

- **IP**: octet-validated (rejects `999.x.x.x`). Guards skip version strings, so `6.6.114.1-microsoft-standard-WSL2` and `WSL version 2.7.3.0` are left intact rather than mistaken for IPs.
- **EMAIL**: rejects systemd unit names (`getty@tty1.service`, `user@1000.service`) whose suffix only looks like a domain TLD.
- **USERID**: catches `uid=`/`user=` forms **and** the username segment inside filesystem paths — `/home/<user>/`, `/Users/<user>/`, `/mnt/c/Users/<user>/` — so e.g. `/mnt/c/Users/prade_rgs2it/…` becomes `/mnt/c/Users/[REDACTED:USERID]/…`.
- **PHONE**: requires real separators (`555-867-5309`, `(555) 867-5309`), so bare long integers like epoch timestamps (`1779983210`) no longer false-match.

## Known Limitations

- **Hostnames are not redacted** by design (field 2 of each syslog line, e.g. `pradeep`). They're useful for multi-host grouping and conventionally low-sensitivity; redact them via a custom `--config` pattern if needed.
- IPs and version strings not adjacent to a `-suffix` or the word `version` remain ambiguous — a standalone `1.2.3.4` is always treated as an IP.
- Path-based username detection keys off `/home/`, `/Users/`, `/mnt/c/Users/`; usernames in other path shapes won't be caught.

## Roadmap

- v4: AI-powered log summarization via Claude API (`--ai-summary` flag)
- v5: HTML report generation
- v6: Anomaly detection using pattern recognition

## Author

Soma Das  
GitHub: somaxcodes  
LinkedIn: linkedin.com/in/realsoma  
LTP Upstream Contributor (May 2026 Release)
