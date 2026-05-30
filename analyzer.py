FILTER_KEYWORDS = [
    "ERROR", "WARNING", "CRITICAL", "Failed", "failed", "error", "warning"
]


def read_log(filepath: str) -> list[str]:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\n") for line in f if line.strip()]
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {filepath}")


def filter_issues(lines: list[str]) -> list[str]:
    return [line for line in lines if any(kw in line for kw in FILTER_KEYWORDS)]
