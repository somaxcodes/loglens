import os
import re
from collections import Counter
from dataclasses import dataclass

from dotenv import load_dotenv
from groq import (
    Groq,                  # the API client itself
    APIConnectionError,    # never reached Groq at all — DNS, network down, or the request timed out
    AuthenticationError,   # Groq rejected the API key itself (bad or revoked key)
    GroqError,              # base class for every error the SDK defines — catch-all within the SDK
    RateLimitError,         # Groq accepted the key but is throttling this account
)

from redactor import redact_line
'''
`.env` is where I store my API key locally.

`load_dotenv()` reads the `.env` file and makes the values available in the program's environment.

Then `os.getenv("GROQ_API_KEY")` asks the environment, "What is the value of GROQ_API_KEY?"

The Python code doesn't need to know where the key came from. It only asks the environment for the key. On a server or CI system, the key can be provided directly as an environment variable without using a `.env` file.
'''

# Reads the .env file in the project root and copies anything in it into the
# environment, so os.getenv() below can find GROQ_API_KEY. Harmless no-op if
# there is no .env (e.g. CI, where the key comes from a real env var instead).
load_dotenv()

GROQ_MODEL = "openai/gpt-oss-20b"

# How much of each list we send. The tail of a Counter is mostly one-off noise:
# it costs tokens and dilutes the model's attention without adding signal.
TOP_PATTERNS = 8
TOP_SERVICES = 5

# Standing instructions for the model: who it is and what shape the answer takes.
# Kept close to fallback_analysis()'s output so both render the same in cli.py's Panel.
SYSTEM_PROMPT = """You are a Linux systems engineer triaging a log file.
You are given a statistical summary of the issues found, not the raw log.

Reply with at most 8 short lines of plain text:
- a one-line health verdict and what it is based on
- the most likely root cause of the dominant pattern
- one concrete next command or file to check

Rules: plain text only, no markdown, no bullets, no preamble, no restating
the numbers back. Say "insufficient evidence" rather than guessing."""


def shorten(text: str, width: int = 100) -> str:
    text = text.strip()
    return text if len(text) <= width else text[:width - 1].rstrip() + "…"


# Matches a redaction placeholder like "[REDACTED:EMAIL]" as one whole unit.
_REDACTED_TAG = re.compile(r'\[REDACTED:[^\]]+\]')


def _shorten_keep_tag_whole(text: str, width: int = 100) -> str:
    """
    Same rule as shorten(), except: if the width cutoff would land inside a
    [REDACTED:...] placeholder, push the cut to the end of that placeholder
    instead of slicing through it. Used only in _build_prompt() — the AI path —
    where a tag reading "[REDACTED:EMAI" is confusing to send to a model, and a
    result a few characters over budget is a fine trade for the tag staying whole.
    Not applied to the plain shorten() used by fallback_analysis(), which only
    ever prints to this machine's own terminal — a cut tag there is cosmetic.
    """
    text = text.strip()
    if len(text) <= width:
        return text

    cut = width - 1  # shorten()'s original cut point, before the "…" is appended
    for m in _REDACTED_TAG.finditer(text):
        if m.start() < cut < m.end():
            cut = m.end()  # extend the cut past the whole tag
            break          # the cut point can only fall inside one tag at a time

    return text[:cut].rstrip() + "…"


def _categorize(pattern: str) -> str:
    p = pattern.lower()
    if any(kw in p for kw in ("connect", "agent", "address", "getaddrinfo", "network")):
        return "Connectivity / network configuration issue"
    if any(kw in p for kw in ("permission", "denied", "access")):
        return "Access control / permission issue"
    if "timeout" in p:
        return "Performance / timeout issue"
    if any(kw in p for kw in ("not found", "no such file", "missing")):
        return "Missing file or configuration"
    if any(kw in p for kw in ("failed", "failure")):
        return "Operation failure — check service logs for details"
    return ""


def _health_label(severity: dict[str, int], total: int) -> str:
    # Ladder worst→best: CRITICAL > UNHEALTHY > DEGRADED > HEALTHY
    if severity.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if total > 0 and severity.get("ERROR", 0) / total > 0.30:
        return "UNHEALTHY"   # high error rate = worse
    if severity.get("ERROR", 0) > 0:
        return "DEGRADED"    # some errors = degraded (less bad than high rate)
    if severity.get("WARNING", 0) > 10:
        return "DEGRADED"
    return "HEALTHY"


def _recommendation(health: str, category: str) -> str:
    if health == "CRITICAL":
        return "Immediate action required — critical errors detected."
    if category == "Connectivity / network configuration issue":
        return "Check network connectivity and agent/service configuration on the Windows side."
    if category == "Access control / permission issue":
        return "Review file permissions and user/group ownership."
    if category == "Performance / timeout issue":
        return "Investigate slow services or resource contention causing timeouts."
    if category == "Missing file or configuration":
        return "Verify all required config files and packages are installed."
    if health == "DEGRADED":
        return "Multiple error classes detected — start with the most frequent pattern."
    return "Review the top patterns above for the most actionable leads."


def fallback_analysis(
    patterns: Counter,
    severity: dict[str, int],
    services: dict[str, list] | None = None,
) -> str:
    total = sum(severity.values())
    if total == 0:
        return "No issues detected."

    health = _health_label(severity, total)
    lines = []

    lines.append(
        f"Health: {health}  |  "
        f"{total} total — "
        f"{severity.get('CRITICAL',0)} critical, "
        f"{severity.get('ERROR',0)} errors, "
        f"{severity.get('WARNING',0)} warnings, "
        f"{severity.get('UNKNOWN',0)} unknown"
    )
    lines.append("")

    top_category = ""
    if patterns:
        top_pattern, top_count = patterns.most_common(1)[0]
        occurrence_total = sum(patterns.values())
        pct = top_count / occurrence_total * 100
        if pct >= 20:
            top_category = _categorize(top_pattern)
            lines.append(f"Primary issue ({pct:.0f}% of all issues):")
            lines.append(f"  {shorten(top_pattern)}")
            if top_category:
                lines.append(f"  → {top_category}")
            lines.append("")

        rest = patterns.most_common(6)[1:5]
        if rest:
            lines.append("Other recurring issues:")
            for pat, cnt in rest:
                lines.append(f"  • {shorten(pat, 90)} ({cnt}×)")
            lines.append("")

    if services:
        top_service = max(services, key=lambda s: len(services[s]))
        top_service_count = len(services[top_service])
        if total > 0 and top_service_count / total >= 0.40:
            lines.append(
                f"Noisiest service: {top_service} "
                f"({top_service_count}/{total} issues, {top_service_count/total*100:.0f}%)"
            )
            lines.append("")

    lines.append(f"Recommendation: {_recommendation(health, top_category)}")
    return "\n".join(lines)


def _build_prompt(
    patterns: Counter,
    severity: dict[str, int],
    services: dict[str, list] | None = None,
) -> str:
    """Flatten the analyzer's counts into the plain-text summary we send to Groq."""
    total = sum(severity.values())

    lines = [
        f"Total issue lines: {total}",
        (
            "Severity breakdown: "
            f"{severity.get('CRITICAL', 0)} critical, "
            f"{severity.get('ERROR', 0)} errors, "
            f"{severity.get('WARNING', 0)} warnings, "
            f"{severity.get('UNKNOWN', 0)} unknown"
        ),
        "",
        "Most frequent issue patterns:",
    ]

    for pattern, count in patterns.most_common(TOP_PATTERNS):
        # Redact BEFORE shortening: truncating first can cut a PII match in half
        # (e.g. "soma.das@exampl…"), and a half-match slips past the regex entirely.
        safe_pattern, _ = redact_line(pattern)
        lines.append(f"  {count}x  {_shorten_keep_tag_whole(safe_pattern, 160)}")

    if services:
        ranked = sorted(services.items(), key=lambda kv: len(kv[1]), reverse=True)
        lines.append("")
        lines.append("Issue counts by service:")
        for name, entries in ranked[:TOP_SERVICES]:
            lines.append(f"  {name}: {len(entries)}")

    prompt = "\n".join(lines)

    # Belt-and-braces final pass: catches PII in the parts of the prompt that aren't
    # per-pattern text (e.g. service names). Unconditional on purpose: --redact
    # controls what the user sees locally, a separate question from what may leave
    # the machine. Safe to run twice — replacing PII in text with no PII left is a
    # no-op (idempotent) — as long as redaction always happens before truncation.
    # Limitation: built-in PII_PATTERNS only — custom --config patterns live in
    # cli.py and never reach this module.
    safe_prompt, _ = redact_line(prompt)
    return safe_prompt


def run_ai_analysis(
    patterns: Counter,
    severity: dict[str, int],
    services: dict[str, list] | None = None,
) -> str:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set — add it to your .env file")

    client = Groq(api_key=api_key)
    '''
    this does not contact Groq. Nothing is sent, no key is verified. It builds a local object that holds your key and a pooled HTTP connection, ready to make requests.
    '''

    prompt = _build_prompt(patterns, severity, services)

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )
    return response.choices[0].message.content.strip()


@dataclass
class AnalysisResult:
    """
    What analyse() actually did. cli.py needs this to report whether AI ran or
    silently fell back and why — but ai_analysis.py has no `rich`/console
    dependency and never prints anything itself, so that information has to
    travel back as data rather than as a side-effect print. cli.py decides how
    (or whether) to display it.
    """
    text: str                    # the analysis text to show, either way
    mode: str                    # "ai" — Groq answered; "rule" — the rule-based fallback ran
    ai_error: str | None = None  # set only when use_ai=True but the AI path failed; explains why


def analyse(
    patterns: Counter,
    severity: dict[str, int],
    services: dict[str, list] | None = None,
    use_ai: bool = False,
) -> AnalysisResult:
    if not use_ai:
        text = fallback_analysis(patterns, severity, services)
        return AnalysisResult(text=text, mode="rule")

    try:
        text = run_ai_analysis(patterns, severity, services)
        return AnalysisResult(text=text, mode="ai")
    except AuthenticationError:
        reason = "invalid or missing GROQ_API_KEY"
    except RateLimitError:
        reason = "Groq rate limit hit"
    except APIConnectionError:
        # APITimeoutError is a subclass of APIConnectionError, so a plain
        # timeout is caught here too — both mean "never got a response back".
        reason = "network/timeout error reaching Groq"
    except GroqError as e:
        # Any other error the SDK itself defines that isn't one of the three
        # specific cases above (e.g. a malformed response from the API).
        reason = f"Groq API error ({type(e).__name__})"
    except Exception as e:
        # Not from the Groq SDK at all — e.g. our own RuntimeError from
        # run_ai_analysis() when GROQ_API_KEY isn't set in the environment.
        reason = f"unexpected error ({type(e).__name__})"

    text = fallback_analysis(patterns, severity, services)
    return AnalysisResult(text=text, mode="rule", ai_error=reason)


if __name__ == "__main__":
    import sys

    # Real data from sample1_syslog.log V3 output
    sample_patterns: Counter = Counter({
        'WARNING Daemon: could not connect to Windows Agent: could not get address: could not read agent port file "/mnt/c/Users/prade_rgs2it/.ubuntupro/.address": open /mnt/c/Users/prade_rgs2it/.ubuntupro/.address: no such file or directory': 33,
        "WSL (270) ERROR: CheckConnection: getaddrinfo() failed: -5": 6,
        "WSL (2 - init-systemd(Ubuntu)) WARNING: /usr/share/zoneinfo/Asia/Calcutta not found. Is the tzdata package installed?": 4,
        "WARNING Exiting after <nil>: check if the Windows agent is installed and running.": 4,
        "message repeated 3 times: [ WARNING Daemon: could not connect to Windows Agent...]": 2,
        "message repeated 2 times: [ WARNING Daemon: could not connect to Windows Agent...]": 2,
    })
    sample_severity = {"CRITICAL": 0, "ERROR": 21, "WARNING": 52, "UNKNOWN": 5}
    sample_services = {
        "wsl-pro-service": [""] * 47,
        "kernel": [""] * 21,
        "python3": [""] * 3,
        "systemd": [""] * 2,
        "snapd": [""] * 2,
        "sh": [""] * 1,
        "chronyd-starter.sh": [""] * 1,
        "ubuntu-insights": [""] * 1,
    }

    if "--json" in sys.argv:
        import json
        print(json.dumps({
            "health": _health_label(sample_severity, sum(sample_severity.values())),
            "severity": sample_severity,
            "top_pattern": sample_patterns.most_common(1)[0][0],
        }, indent=2))
    else:
        print(analyse(sample_patterns, sample_severity, services=sample_services))
