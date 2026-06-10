import re
from collections import defaultdict

# Each key is the PII type label used in [REDACTED:TYPE] placeholders
PII_PATTERNS: dict[str, re.Pattern] = {
    "IP":     re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),  # e.g. 192.168.1.1; rejects 999.x.x.x but note x.x.x.x with valid octets (e.g. 6.6.114.1) still matches
    "EMAIL":  re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),  # e.g. user@example.com
    "USERID": re.compile(r'\buid=\d+(?:\([^)]+\))?|\buser=[a-zA-Z0-9_]+'),         # e.g. uid=1000(john) or user=john
    "PHONE":  re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),  # e.g. 555-867-5309
}


def redact_line(line: str) -> tuple[str, dict[str, int]]:
    """Scan one log line, replace all PII matches, return the cleaned line and a hit count per type."""
    counts: dict[str, int] = {}
    result = line
    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(result)
        if matches:
            counts[pii_type] = len(matches)
            result = pattern.sub(f"[REDACTED:{pii_type}]", result)  # replace every match in-place
    return result, counts


def redact_lines(
    lines: list[str],
    extra_patterns: dict[str, re.Pattern] | None = None,
) -> tuple[list[str], dict[str, int], list[tuple[str, str]]]:
    """
    Redact PII across all lines.
    Args:
        extra_patterns — optional dict of compiled regex patterns loaded from a config file,
                         merged on top of the built-in PII_PATTERNS
    Returns:
        redacted  — the full list of lines with PII replaced
        totals    — aggregate count per PII type across the whole file
        changed   — (original, redacted) pairs only for lines that changed
    """
    # merge built-in patterns with any custom ones from config; custom patterns can also override built-ins
    patterns = {**PII_PATTERNS, **(extra_patterns or {})}

    redacted: list[str] = []
    totals: dict[str, int] = defaultdict(int)
    changed: list[tuple[str, str]] = []  # used for the before/after display in cli.py

    for line in lines:
        result = line
        counts: dict[str, int] = {}
        for pii_type, pattern in patterns.items():
            matches = pattern.findall(result)
            if matches:
                counts[pii_type] = len(matches)
                result = pattern.sub(f"[REDACTED:{pii_type}]", result)
        redacted.append(result)
        for pii_type, count in counts.items():
            totals[pii_type] += count
        if result != line:  # only track lines where something was actually replaced
            changed.append((line, result))

    return redacted, dict(totals), changed
