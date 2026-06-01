"""
what this script does is :
it reads the log file from the cli input and then filters the warnings/errors and then displays them in a colour coded table
"""
import argparse
import sys
from collections import Counter
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
)
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

def display_issues(issues: list[str], filename: str) -> None:
    if not issues:
        console.print(Panel("[bold green]No issues found.[/bold green]", title=filename))
        return

    table = Table(
        title=f"Issues Found in {filename}",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        header_style="bold cyan",
    )
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Log Line", no_wrap=False)

    for i, line in enumerate(issues, start=1):
        color = _row_style(line)
        table.add_row(str(i), Text(line, style=color))

    console.print(table)
    console.print(f"[bold]Total: {len(issues)} issue{'s' if len(issues) != 1 else ''} found[/bold]")


def display_severity_breakdown(breakdown: dict[str, int]) -> None:
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", show_edge=False)
    table.add_column("CRITICAL", justify="center", style="bold red")
    table.add_column("ERROR", justify="center", style="red")
    table.add_column("WARNING", justify="center", style="yellow")
    table.add_row(str(breakdown["CRITICAL"]), str(breakdown["ERROR"]), str(breakdown["WARNING"]))
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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="loglens",
        description="Scan a log file and surface ERROR / WARNING / CRITICAL lines.",
    )
    parser.add_argument("--file", required=True, metavar="PATH", help="Path to the log file")
    args = parser.parse_args()

    filepath = args.file
    filename = Path(filepath).name

    try:
        lines = read_log(filepath)
    except FileNotFoundError as e:
        console.print(Panel(f"[bold red]{e}[/bold red]", title="[red]Error[/red]"))
        sys.exit(1)

    issues = filter_issues(lines)
    display_issues(issues, filename)
    display_severity_breakdown(severity_breakdown(issues))
    display_top_patterns(count_patterns(issues), filename)
    display_service_groups(group_by_service(issues))


if __name__ == "__main__":
    main()
