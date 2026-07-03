from collections import Counter


def shorten(text: str, width: int = 100) -> str:
    text = text.strip()
    return text if len(text) <= width else text[:width - 1].rstrip() + "…"


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


def run_ai_analysis(
    patterns: Counter,
    severity: dict[str, int],
    services: dict[str, list] | None = None,
) -> str:
    raise NotImplementedError("Groq AI integration not yet wired up — use fallback for now.")


def analyse(
    patterns: Counter,
    severity: dict[str, int],
    services: dict[str, list] | None = None,
    use_ai: bool = False,
) -> str:
    if use_ai:
        try:
            return run_ai_analysis(patterns, severity, services)
        except Exception:
            return fallback_analysis(patterns, severity, services)
    return fallback_analysis(patterns, severity, services)


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
