# LogLens

A local tool that reads a Linux log file and tells you what's actually wrong with it in plain English, instead of leaving you to scroll through thousands of lines looking for the ones that matter.

Take one of the sample logs in this repo: 943 raw lines. Only 76 of those are actual problems worth your time, and even those 76 boil down to just 24 distinct issues once LogLens merges the ones that are really the same failure happening over and over. One of those 24, a service unable to connect because a config file is missing, accounts for 86 of the occurrences on its own. So instead of reading 943 lines, you read one ranked list of 24 real problems and know exactly where to start.

## Local by default, network only when you ask for AI

Everything except `--ai` runs entirely on your machine: reading, parsing, redacting, and pattern-matching are all local, nothing sent anywhere. `--ai` is the one exception. It sends a short statistical summary (counts and the top few patterns, not the raw log) to Groq's API for a plain-English explanation. That summary is always redacted first, whether or not you also passed `--redact`, so it isn't a flag you have to remember to combine correctly. If the AI call fails for any reason (bad key, network down, rate limit), LogLens falls back to a fully offline, rule-based summary automatically and tells you which of those happened and why.

## What it does

- **Parses standard Linux syslog**, both the classic `Mon DD HH:MM:SS` format (what you get from OpenSSH, auth.log, kern.log) and ISO 8601 timestamps. It works out which one it is line by line, no flag needed.
- **Groups repeats into one problem, not fifty.** Real logs repeat the same failure with small differences each time (a changing IP, port, or process ID), and also sometimes literally say "message repeated N times: [...]" in the syslog itself. LogLens normalizes the parts that change and unwraps those repeat-count lines, so the same underlying failure collapses into a single ranked entry instead of cluttering the list.
- **Redacts PII with the actual false positives handled, not just a regex.** A plain "find anything that looks like an email" rule flags `user@1000.service` (a systemd unit name) as someone's email address. LogLens's pattern explicitly rejects unit-name suffixes, so it doesn't. A plain IP-finder misses addresses written with dashes instead of dots inside hostnames (`customer-187-141-143-180-sta.example.com`); LogLens catches those too, while still leaving kernel/driver version strings like `6.6.114.1-microsoft-standard-WSL2` alone. These are specific, tested cases, not a general claim. See `tests/test_redactor.py`.
- **Explains errors in plain language via AI (`--ai`, optional).** Instead of a one-line verdict, it walks through its reasoning: what it's looking at, what that means, why it matters, and it explains any technical term the first time it uses it. It also adjusts tone to the situation, calm and explanatory for a minor issue, direct and urgent when the data shows something genuinely critical.
- **Grades severity and groups by service**: CRITICAL / ERROR / WARNING / UNKNOWN, and which service (sshd, kernel, systemd, etc.) is generating the most noise.
- **Shows when things happened**: first/last issue, total duration, issues per hour, and which hour had the most activity.

None of this requires knowing what "syslog," "severity," or "PII" mean going in. Read a few of the AI explanations and you start recognizing the patterns yourself. That's a deliberate goal of this project, not a side effect.

## Quick start

```bash
pip install -r requirements.txt
python3 cli.py --file samples/sample1_syslog.log
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

# AI-powered plain-language analysis (requires GROQ_API_KEY in .env)
python3 cli.py --file samples/sample1_syslog.log --ai
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
| `--ai` | Show a plain-language AI analysis via Groq; falls back to a rule-based summary if the AI call fails |

## Sample Output

Everything below is real output from an actual run against `samples/sample1_syslog.log`. Nothing here is written for demonstration.

```
PII Summary — 106 items redacted across all log lines (issue + non-issue)
 Type     Redacted
 IP             17
 EMAIL           2
 USERID         87
 TOTAL         106

Issues Found in sample1_syslog.log
 #   Keyword   Log Line
 1   denied    ... sh[105]: /bin/sh: 1: cannot create /proc/sys/fs/binfmt_misc/WSLInterop: Permission denied
 2   failed    ... kernel: Failed to register legacy timer interrupt
 3   warning   ... kernel: Speculative Return Stack Overflow: WARNING: See https://kernel.org/... for mitigation options.
...
Total: 76 issues found

Severity Breakdown
 CRITICAL   ERROR   WARNING   UNKNOWN
     1        23       52         0

Summary Statistics
 First issue    2026-05-28 15:47:10
 Last issue     2026-05-29 14:33:10
 Duration       22h 45m
 Issues/hour    3.3
 Peak hour      15:00–16:00 (37 issues)

Top Patterns in sample1_syslog.log
 Rank   Count   Pattern
    1      86   WARNING Daemon: could not connect to Windows Agent: could not get address:
                 could not read agent port file "/mnt/c/Users/[REDACTED:USERID]/.ubuntupro/.address"...
    2       6   WSL (270) ERROR: CheckConnection: getaddrinfo() failed: -5
...
Showing 10 of 24 unique patterns

Issues by Service
 Service              Issue Count
 wsl-pro-service               47
 kernel                        19
 python3                        3
...
```

### Sample `--ai` Output

```
AI Analysis
The log shows a truly critical state. With 76 lines of trouble, one line is
marked critical, 23 are errors, and 52 are warnings. That mix means the
system is not just a few hiccups; something fundamental is broken and needs
immediate attention.

The most glaring problem is the 86 warnings that the "Daemon" cannot connect
to the Windows Agent because it can't read the address file at
/mnt/c/Users/[REDACTED:USERID]/.ubuntupro/.address. In plain terms, the WSL
side is trying to talk to a helper program that lives on the Windows side,
but it can't find the file that tells it where that helper is listening...

Here's what to check first: confirm whether the Windows Agent is actually
running and that the address file exists. On the Windows host, look for a
service named "Windows Subsystem for Linux" or "Ubuntu Agent" and start it
if it's stopped. Then, on the WSL side, run `cat
/mnt/c/Users/[REDACTED:USERID]/.ubuntupro/.address` to confirm the file is
present and contains a valid port number.

If that doesn't turn up anything, try this next: verify the Windows user has
permission to write to the `.ubuntupro` directory, or check DNS resolution
inside WSL with `nslookup google.com`.
```

## PII Redaction Details

- **IP**: octet-validated (rejects `999.x.x.x`). Guards skip version strings, so `6.6.114.1-microsoft-standard-WSL2` and `WSL version 2.7.3.0` are left intact rather than mistaken for IPs.
- **EMAIL**: rejects systemd unit names (`getty@tty1.service`, `user@1000.service`) whose suffix only looks like a domain TLD.
- **USERID**: catches `uid=`/`user=` forms **and** the username segment inside filesystem paths: `/home/<user>/`, `/Users/<user>/`, `/mnt/c/Users/<user>/`. So e.g. `/mnt/c/Users/prade_rgs2it/…` becomes `/mnt/c/Users/[REDACTED:USERID]/…`.
- **PHONE**: requires real separators (`555-867-5309`, `(555) 867-5309`), so bare long integers like epoch timestamps (`1779983210`) no longer false-match.
- The `--ai` path redacts the outgoing prompt through this same engine before it leaves the machine, unconditionally. See `tests/test_ai_analysis.py` for the tests that pin this down, including a regression test for a real leak found and fixed during development (a username that slipped through at a text-truncation boundary).

## Known Limitations

- **Hostnames are not redacted** by design (field 2 of each syslog line, e.g. `pradeep`). They're useful for multi-host grouping and conventionally low-sensitivity; redact them via a custom `--config` pattern if needed.
- IPs and version strings not adjacent to a `-suffix` or the word `version` remain ambiguous. A standalone `1.2.3.4` is always treated as an IP.
- Path-based username detection keys off `/home/`, `/Users/`, `/mnt/c/Users/`; usernames in other path shapes won't be caught.
- Only syslog-style logs are parsed into structured fields (timestamp/host/service/pid). Other formats (application stack traces, Windows Event Log, JSON logs) are not currently supported.
- **No environment awareness.** Both the rule-based analysis and the AI explanation reason about what a pattern would usually mean on a standard Linux system. They don't know whether the log came from bare metal, a VM, a container, or WSL. A line that's a routine part of one environment can read as more (or less) significant than it actually is if that environment isn't accounted for. WSL-specific context is on the Roadmap below for exactly this reason.

## Testing

```bash
python3 -m pytest tests/ -q
```

83 tests as of this writing, covering the parser, the redactor (including the false-positive cases above), the rule-based analysis, and the AI path (prompt building, the redaction guarantee, and each of Groq's failure modes falling back correctly).

## Roadmap

- WSL environment detection: recognize WSL-specific log patterns and tailor the analysis to that environment
- Chat interface: ask follow-up questions about a log instead of a one-shot summary
- HTML report generation
- Anomaly detection using pattern recognition

## Author

Soma Das  
GitHub: somaxcodes  
LinkedIn: linkedin.com/in/realsoma  
LTP Upstream Contributor (May 2026 Release)
