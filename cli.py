"""
what this script does is :
it reads the log file from the cli input and then filters the warnings/errors and then displays them in a colour coded table
"""
import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text
"""
what rich does:
Makes terminal output look beautiful
Adds colors, tables, panels
"""
from analyzer import (
    read_log,
    filter_issues,
    severity_breakdown,
    count_patterns,
    group_by_service,
    strip_ansi,
    parse_syslog_line,
)
from redactor import redact_lines
from ai_analysis import analyse
# redact_lines() scrubs PII from all log lines before analysis when --redact is passed
"""
from analyzer.py :
it reads the log file using read_log()
it finds errors using filter_issues() based on the keywords we provided
"""
console = Console()
#this creates your print engine
#we are not using print because console supports formatting and colours

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "ERROR":    "red",
    "Failed":   "red",
    "failed":   "red",
    "error":    "red",
    "WARNING":  "yellow",
    "warning":  "yellow",
}
#all warnings/errors are mapped to certain colours

def _row_style(line: str) -> str:
    line_lower = line.lower()
    for keyword, color in SEVERITY_COLORS.items():
        #it checkes if the string has any of the keywords from severity colours and then returns a colour
        if keyword.lower() in line_lower:
            return color
    return "white"
"""
This is basic string matching
Case-sensitive
Not scalable
"""

def display_issues(issues: list[tuple[str, str]], filename: str, limit: int = 50) -> None:
    if not issues:
        console.print(Panel("[bold green]No issues found.[/bold green]", title=filename))
        return

    shown = issues if limit == 0 else issues[:limit]

    table = Table(
        title=f"Issues Found in {filename}",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        header_style="bold cyan",
    )
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Keyword", style="bold", no_wrap=True)
    table.add_column("Log Line", no_wrap=False)

    for i, (line, keyword) in enumerate(shown, start=1):
        clean = strip_ansi(line)
        color = _row_style(clean)
        text = Text(clean, style=color)
        text.highlight_regex(rf'(?i)\b{re.escape(keyword)}\b', style="bold underline reverse")
        text.highlight_regex(r'\[REDACTED:[A-Z]+\]', style="bold magenta")
        table.add_row(str(i), keyword, text)

    console.print(table)
    console.print(f"[bold]Total: {len(issues)} issue{'s' if len(issues) != 1 else ''} found[/bold]")
    if limit and len(issues) > limit:
        console.print(f"[dim]Showing {limit} of {len(issues)} — pass --limit N for more, --limit 0 for all[/dim]")


def display_severity_breakdown(breakdown: dict[str, int]) -> None:
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", show_edge=False)
    table.add_column("CRITICAL", justify="center", style="bold red")
    table.add_column("ERROR", justify="center", style="red")
    table.add_column("WARNING", justify="center", style="yellow")
    table.add_column("UNKNOWN", justify="center", style="dim")  # lines caught by broad keywords with no severity label
    table.add_row(
        str(breakdown["CRITICAL"]),
        str(breakdown["ERROR"]),
        str(breakdown["WARNING"]),
        str(breakdown.get("UNKNOWN", 0)),
    )
    console.print(Panel(table, title="Severity Breakdown"))


def display_top_patterns(counter: Counter, filename: str) -> None:
    if not counter:
        console.print(Panel("[dim]No repeated patterns detected.[/dim]", title="Top Patterns"))
        return

    top = counter.most_common(10)
    table = Table(
        title=f"Top Patterns in {filename}",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        header_style="bold cyan",
    )
    table.add_column("Rank", justify="right", style="dim", no_wrap=True)
    table.add_column("Count", justify="right", no_wrap=True)
    table.add_column("Pattern", no_wrap=False)

    for rank, (pattern, count) in enumerate(top, start=1):
        color = _row_style(pattern)
        table.add_row(str(rank), str(count), Text(pattern, style=color))

    console.print(table)
    shown = min(10, len(counter))
    console.print(f"[dim]Showing {shown} of {len(counter)} unique pattern{'s' if len(counter) != 1 else ''}[/dim]")


def display_service_groups(groups: dict[str, list[str]]) -> None:
    if not groups:
        console.print(Panel("[dim]No service data available.[/dim]", title="Issues by Service"))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", show_edge=False)
    table.add_column("Service", style="cyan")
    table.add_column("Issue Count", justify="right")

    for service, lines in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True):
        count = len(lines)
        color = "red" if count >= 10 else "yellow" if count >= 3 else "dim"
        table.add_row(service, Text(str(count), style=color))

    console.print(Panel(table, title="Issues by Service"))


def display_before_after(changed_pairs: list[tuple[str, str]]) -> None:
    # shows a side-by-side table of lines that had PII replaced
    if not changed_pairs:
        console.print(Panel("[dim]No PII found in this log.[/dim]", title="PII Redaction — Before / After"))
        return

    cap = 20  # avoid flooding the terminal on large logs
    shown = changed_pairs[:cap]

    table = Table(box=box.SIMPLE_HEAD, show_lines=True, header_style="bold cyan")
    table.add_column("Before", no_wrap=False)
    table.add_column("After", no_wrap=False)

    for original, redacted in shown:
        # truncate long lines so the table stays readable
        orig_display = original[:120] + "…" if len(original) > 120 else original
        redc_display = redacted[:120] + "…" if len(redacted) > 120 else redacted
        table.add_row(Text(orig_display, style="yellow"), Text(redc_display, style="green"))

    note = f"showing {len(shown)} of {len(changed_pairs)} changed lines"
    console.print(Panel(table, title=f"PII Redaction — Before / After ({note})"))


def display_pii_summary(counts: dict[str, int]) -> None:
    # shows how many of each PII type were found across the whole file
    if not counts:
        console.print(Panel("[dim]No PII detected.[/dim]", title="PII Summary"))
        return

    PII_COLORS = {"IP": "cyan", "EMAIL": "magenta", "USERID": "yellow", "PHONE": "blue"}
    total = sum(counts.values())

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", show_edge=False)
    table.add_column("Type", style="bold")
    table.add_column("Redacted", justify="right")

    for pii_type, count in counts.items():
        color = PII_COLORS.get(pii_type, "white")
        table.add_row(Text(pii_type, style=color), str(count))

    table.add_section()
    table.add_row(Text("TOTAL", style="bold white"), Text(str(total), style="bold white"))

    console.print(Panel(table, title=f"PII Summary — {total} item{'s' if total != 1 else ''} redacted across all log lines (issue + non-issue)"))


def display_summary_stats(issues: list[tuple[str, str]]) -> None:
    timestamps = []
    for line, _ in issues:
        parsed = parse_syslog_line(line)
        if not parsed:
            continue
        ts = parsed["timestamp"]
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            try:
                dt = datetime.strptime(ts, "%b %d %H:%M:%S").replace(year=datetime.now().year)
            except ValueError:
                continue
        timestamps.append(dt)

    if len(timestamps) < 2:
        return

    timestamps.sort()
    first, last = timestamps[0], timestamps[-1]
    duration_secs = (last - first).total_seconds()
    total_hours = duration_secs / 3600
    rate = len(timestamps) / total_hours if total_hours > 0 else 0
    h, rem = divmod(int(duration_secs), 3600)
    duration_str = f"{h}h {rem // 60}m"

    hour_counts: Counter = Counter(dt.hour for dt in timestamps)
    peak_hour, peak_count = hour_counts.most_common(1)[0]

    table = Table(box=box.SIMPLE, show_header=False, show_edge=False, pad_edge=False)
    table.add_column("Label", style="bold cyan", no_wrap=True)
    table.add_column("Value", no_wrap=True)
    table.add_row("First issue",  first.strftime("%Y-%m-%d %H:%M:%S"))
    table.add_row("Last issue",   last.strftime("%Y-%m-%d %H:%M:%S"))
    table.add_row("Duration",     duration_str)
    table.add_row("Issues/hour",  f"{rate:.1f}")
    table.add_row("Peak hour",    f"{peak_hour:02d}:00–{peak_hour+1:02d}:00 ({peak_count} issues)")
    console.print(Panel(table, title="Summary Statistics"))


def display_analysis(text: str, mode: str) -> None:
    # mode="ai" title used when Groq integration lands; "rule" is the current default
    title = "AI Analysis" if mode == "ai" else "Rule-based Analysis"
    console.print(Panel(text, title=title))


def load_config(path: str) -> dict[str, re.Pattern]:
    """Read a JSON config file and compile any custom PII patterns it defines."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: re.compile(v) for k, v in data.get("pii_patterns", {}).items()}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="loglens",
        description="Scan a log file and surface ERROR / WARNING / CRITICAL lines.",
    )
    parser.add_argument("--file", required=True, metavar="PATH", help="Path to the log file")
    parser.add_argument("--redact", action="store_true", help="Redact PII (IPs, emails, user IDs, phone numbers) before analysis")
    parser.add_argument("--export", metavar="PATH", help="Write the redacted log to PATH (requires --redact)")
    parser.add_argument("--config", metavar="PATH", help="JSON config with custom PII patterns (requires --redact)")
    parser.add_argument("--limit", type=int, default=50, metavar="N", help="Max issues to display (0 = no limit, default 50)")
    parser.add_argument("--no-color", action="store_true", help="Disable color output (for CI/piped use)")
    parser.add_argument("--ai", action="store_true", help="Show analysis summary (rule-based; Groq AI integration in progress)")
    args = parser.parse_args()

    global console
    if args.no_color:
        console = Console(no_color=True, highlight=False)

    # --export and --config only make sense when redaction is active
    if args.export and not args.redact:
        console.print(Panel("[bold red]--export requires --redact[/bold red]", title="[red]Error[/red]"))
        sys.exit(1)
    if args.config and not args.redact:
        console.print(Panel("[bold red]--config requires --redact[/bold red]", title="[red]Error[/red]"))
        sys.exit(1)

    filepath = args.file
    filename = Path(filepath).name

    try:
        lines = read_log(filepath)
    except FileNotFoundError as e:
        console.print(Panel(f"[bold red]{e}[/bold red]", title="[red]Error[/red]"))
        sys.exit(1)

    if args.redact:
        # load custom patterns from --config, or auto-discover loglens_config.json in CWD
        extra_patterns: dict[str, re.Pattern] = {}
        config_path = args.config or ("loglens_config.json" if Path("loglens_config.json").exists() else None)
        if config_path:
            try:
                extra_patterns = load_config(config_path)
                console.print(Panel(f"[dim]Loaded {len(extra_patterns)} custom pattern(s) from {config_path}[/dim]", title="Config"))
            except Exception as exc:
                console.print(Panel(f"[bold red]Config error: {exc}[/bold red]", title="[red]Error[/red]"))
                sys.exit(1)

        # replace PII in all lines first, then run the rest of the analysis on the clean version
        lines, pii_counts, _ = redact_lines(lines, extra_patterns=extra_patterns)
        display_pii_summary(pii_counts)
        if args.export:
            # write every redacted line to the output file, one per line
            Path(args.export).write_text("\n".join(lines) + "\n", encoding="utf-8")
            console.print(Panel(f"[green]Redacted log saved to {args.export}[/green]", title="Export"))

    issues = filter_issues(lines)
    display_issues(issues, filename, limit=args.limit)
    issue_lines = [line for line, _ in issues]

    # compute once — reused by display functions and AI analysis
    severity = severity_breakdown(issue_lines)
    patterns = count_patterns(issue_lines)
    services = group_by_service(issue_lines)

    display_severity_breakdown(severity)
    display_summary_stats(issues)
    display_top_patterns(patterns, filename)
    display_service_groups(services)

    if args.ai:
        summary = analyse(patterns, severity, services=services)
        display_analysis(summary, mode="rule")


if __name__ == "__main__":
    main()
