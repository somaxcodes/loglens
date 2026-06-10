import re
from collections import Counter

# single compiled regex replaces the old FILTER_KEYWORDS list — catches more variants (failure, fatal, exception, etc.)
_ISSUE_PATTERN = re.compile(
    r'\b(critical|error|fail(ed|ure|ing)?|warning|exception|panic|abort(ed)?|denied|timeout|refused|fatal)\b',
    re.IGNORECASE,
)

_SYSLOG_TRADITIONAL = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+[\d:]+)\s+(\S+)\s+([a-zA-Z0-9_.\-]+?)(?:\[(\d+)\])?:\s*(.*)$'
)
_SYSLOG_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T[\d:.+]+)\s+(\S+)\s+([a-zA-Z0-9_.\-]+?)(?:\[(\d+)\])?:\s*(.*)$'
)
_ANSI_ESCAPE = re.compile(r'(?:\x1b|#033)\[[0-9;]*m')


def strip_ansi(line: str) -> str:
    return _ANSI_ESCAPE.sub('', line)


def read_log(filepath: str) -> list[str]:
    #this function takes a file path and returns a list of lines
    try:
        #r: is read , utf-8: handles text properly ,errors="replace" : if weird characters exist, don't crash → replace them
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\n") for line in f if line.strip()]
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {filepath}")


def filter_issues(lines: list[str]) -> list[tuple[str, str]]:
    #takes the cleaned log lines and returns (line, matched_keyword) for each issue
    result = []
    for line in lines:
        m = _ISSUE_PATTERN.search(strip_ansi(line))
        if m:
            result.append((line, m.group(1).lower()))
    return result


def parse_syslog_line(line: str) -> dict | None:
    clean = strip_ansi(line)
    for pattern in (_SYSLOG_TRADITIONAL, _SYSLOG_ISO):
        m = pattern.match(clean)
        if m:
            return {
                "timestamp": m.group(1),
                "hostname":  m.group(2),
                "service":   m.group(3),
                "pid":       m.group(4),
                "message":   m.group(5),
            }
    return None


def classify_severity(line: str) -> str:
    clean = strip_ansi(line).lower()
    if "critical" in clean:
        return "CRITICAL"
    if any(kw in clean for kw in ("error", "failed")):
        return "ERROR"
    if "warning" in clean:
        return "WARNING"
    # line was caught by a broader keyword (timeout, denied, exception, etc.) with no severity label
    return "UNKNOWN"


def normalize_message(message: str) -> str:
    msg = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<IP>', message)
    msg = re.sub(r'\bport\s+\d+', 'port <PORT>', msg)
    msg = re.sub(r'\b0x[0-9a-fA-F]+\b', '<ADDR>', msg)
    msg = re.sub(r'\b\d{4,}\b', '<NUM>', msg)
    return msg.strip()


def count_patterns(issues: list[str]) -> Counter:
    counter: Counter = Counter()
    for line in issues:
        parsed = parse_syslog_line(line)
        key = normalize_message(parsed["message"] if parsed else strip_ansi(line))
        counter[key] += 1
    return counter


def severity_breakdown(issues: list[str]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "UNKNOWN": 0}
    for line in issues:
        counts[classify_severity(line)] += 1
    return counts


def group_by_service(issues: list[str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for line in issues:
        parsed = parse_syslog_line(line)
        service = parsed["service"] if parsed else "unknown"
        groups.setdefault(service, []).append(line)
    return groups
