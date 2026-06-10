# Changelog

## v3 (2026-06-09)

- PII redaction: IP, email, phone, userid → `[REDACTED:TYPE]` placeholders (`--redact` flag)
- `--export PATH` to save a redacted copy of the log
- `--config PATH` for custom PII patterns via JSON
- `--limit N` flag to cap issues shown (default 50, `--limit 0` for all)
- `--no-color` flag for CI pipelines and plain-text output
- Keyword column in issues table showing which word triggered the issue
- Keyword highlighted (bold underline reverse) inside each log line
- `[REDACTED:TYPE]` tokens highlighted in magenta for visibility
- Summary statistics panel: first/last issue, duration, issues/hour, peak hour
- UNKNOWN severity bucket for broader keywords (timeout, denied, panic, etc.)
- Broader keyword set: `panic`, `denied`, `fatal`, `timeout`, `refused`, `abort`, `exception`, `failure`, `failing`
- PII Summary panel shows count per type across all log lines (issue + non-issue)
- Tightened IP regex to require valid octets (0–255)

## v2

- Severity breakdown panel (CRITICAL / ERROR / WARNING)
- Top patterns panel ranked by frequency
- Issues by service panel
- Color-coded rows by severity

## v1

- Basic log parsing and error detection
- Filtered display of warning/error lines
- Rich-based terminal output
