# LogLens

A Python-based Linux log analyzer that parses syslog files, detects errors and warnings, and surfaces patterns and noisy services in system logs.

## Features

- Parses standard Linux syslog format
- Identifies log severity levels (CRITICAL, ERROR, WARNING)
- Detects repeated patterns and ranks them by frequency
- Groups issues by service to surface the noisiest sources
- Case-insensitive matching to catch compound warnings (e.g. DeprecationWarning)
- Clean structured CLI output using the rich library

## Installation
pip install -r requirements.txt
## Usage
python cli.py --file samples/sample1_syslog.log
## Sample Output

When run against a syslog file, LogLens produces a structured report with four views: issues found, severity breakdown, top repeated patterns, and a breakdown of issues by service.
Issues Found in sample.log
Log Line
─────────────────────────────────────────────────────────────────
1   2026-05-28 ... kernel: Failed to register legacy timer
2   2026-05-28 ... kernel: WSL ERROR: getaddrinfo failed
...
Total: 29 issues found
Severity Breakdown
CRITICAL  ERROR  WARNING
0      14       15
Top Patterns
Rank   Count   Pattern
1      9       WARNING Daemon: could not connect to Windows Agent
2      1       Failed to register legacy timer interrupt
3      1       WSL ERROR: CheckConnection: getaddrinfo failed
...
Issues by Service
Service              Issue Count
kernel               12
wsl-pro-service      11
systemd              2
snapd                1
## Roadmap

- v3: PII redaction (regex-based redaction of IPs, emails, user IDs)
- v4: pytest-based unit tests for parser and severity classification
- v5: HTML report generation
- v6: Anomaly detection using pattern recognition

## Author

Soma Das  
GitHub: somaxcodes  
LinkedIn: linkedin.com/in/realsoma  
LTP Upstream Contributor (May 2026 Release)
