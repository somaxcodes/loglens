import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from analyzer import read_log, filter_issues

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "ERROR":    "red",
    "Failed":   "red",
    "failed":   "red",
    "error":    "red",
    "WARNING":  "yellow",
    "warning":  "yellow",
}


def _row_style(line: str) -> str:
    for keyword, color in SEVERITY_COLORS.items():
        if keyword in line:
            return color
    return "white"


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


if __name__ == "__main__":
    main()
