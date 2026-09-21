import re
from collections import defaultdict

# systemd unit suffixes that a naive EMAIL regex mistakes for a domain TLD
# (e.g. "user@1000.service", "getty@tty1.service" are unit names, not emails)
_UNIT_SUFFIXES = (
    "service", "socket", "target", "mount", "automount",
    "scope", "slice", "timer", "path", "device", "swap",
)
_UNIT_TLD_GUARD = "".join(rf"(?!{s}\b)" for s in _UNIT_SUFFIXES)

# a single 0-255 octet, reused by both the dotted and dashed IP forms
_OCTET = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
# Reverse-DNS hostnames often embed the IP with dashes instead of dots:
#   customer-187-141-143-180-sta.uninet-ide.com.mx   → 187.141.143.180
#   ec2-52-80-34-196.cn-north-1.compute.amazonaws.com
# The dotted-quad regex misses these entirely, leaking the address in plain sight.
# The quad must be preceded by a label that contains a letter, or by a plain delimiter. That
# is what separates a hostname from a dashed timestamp: in "backup-2026-05-28-15-47-10" every
# candidate quad is preceded only by digits and dashes, so none of these lookbehinds fire.
# Python needs each lookbehind fixed-width, hence the alternation rather than one expression.
_HOSTNAME_LABEL_PREFIX = (
    r'(?:(?<=[A-Za-z]-)'      # customer-187-...
    r'|(?<=[A-Za-z]\d-)'      # ec2-52-...
    r'|(?<=[A-Za-z]\d{2}-)'   # abc12-52-...
    r'|(?<=[\s=(\[]))'        # rhost=187-...
)
# Trailing guard: reject a digit (mid-octet) or another -digit group (a longer dashed sequence),
# while still allowing a following text label as in "...-180-sta".
_DASHED_IP = rf'{_HOSTNAME_LABEL_PREFIX}{_OCTET}-{_OCTET}-{_OCTET}-{_OCTET}(?!\d)(?!-\d)'

# Each key is the PII type label used in [REDACTED:TYPE] placeholders
PII_PATTERNS: dict[str, re.Pattern] = {
    # e.g. 192.168.1.1. Octet-validated (rejects 999.x.x.x). Two guards avoid
    # eating version strings that look like dotted numbers:
    #   (?<!version )  → skip "WSL version 2.7.3.0"
    #   (?!-)          → skip "6.6.114.1-microsoft", "1.0.7.0-k" (kernel/driver versions)
    "IP":     re.compile(
        rf'(?<!version )\b(?:{_OCTET}\.){{3}}{_OCTET}\b(?!-)'
        rf'|{_DASHED_IP}'
    ),
    # real email; the _UNIT_TLD_GUARD after the final dot rejects systemd unit names
    "EMAIL":  re.compile(rf'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.{_UNIT_TLD_GUARD}[a-zA-Z]{{2,}}\b'),
    # uid=/user= forms, PLUS the username segment inside a filesystem path.
    # The lookbehinds match only the <user> in /home/<user>/, /Users/<user>/,
    # /mnt/c/Users/<user>/ — so the surrounding path is preserved:
    #   /mnt/c/Users/prade_rgs2it/... → /mnt/c/Users/[REDACTED:USERID]/...
    "USERID": re.compile(
        r'\buid=\d+(?:\([^)]+\))?'
        r'|\buser=[a-zA-Z0-9_]+'
        r'|(?:(?<=/home/)|(?<=/Users/))[A-Za-z0-9_.\-]+'
    ),
    # phone number — separators are now REQUIRED between groups, so bare long
    # integers (epoch timestamps like 1779983210, counters like 2147483648)
    # no longer match. Accepts 555-867-5309, (555) 867-5309, +1 555 867 5309.
    "PHONE":  re.compile(r'\b(?:\+?1[-.\s])?(?:\(\d{3}\)\s?|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b'),
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
