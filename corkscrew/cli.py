"""CLI interface for CorkScrew."""
import io
import json
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .analyzer import AnalysisResult, TerraformAnalyzer

# Fix Windows console encoding issues
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

console = Console()


def get_score_color(score: float) -> str:
    """Return color based on synthetic score."""
    if score >= 75:
        return "red"
    elif score >= 50:
        return "yellow"
    elif score >= 30:
        return "cyan"
    return "green"


def get_severity_indicator(severity: float) -> str:
    """Return severity indicator."""
    if severity >= 0.7:
        return "[red]●●●[/red]"
    elif severity >= 0.4:
        return "[yellow]●●○[/yellow]"
    return "[green]●○○[/green]"


def get_provider_display(provider: str) -> str:
    """Return provider display string with color."""
    provider_map = {
        "aws": "[orange1]AWS[/orange1]",
        "gcp": "[blue]GCP[/blue]",
        "multi": "[magenta]Multi-Cloud[/magenta]",
        "unknown": "[dim]Unknown[/dim]",
    }
    return provider_map.get(provider, provider)


def render_result(result: AnalysisResult, verbose: bool = False) -> None:
    """Render analysis result to console."""
    # Header with score
    score_color = get_score_color(result.synthetic_score)

    verdict = result.to_dict()["verdict"]
    provider_display = get_provider_display(result.provider)
    console.print()
    console.print(Panel(
        f"[bold {score_color}]Synthetic Score: {result.synthetic_score:.1f}/100[/bold {score_color}]\n\n"
        f"[{score_color}]{verdict}[/{score_color}]\n\n"
        f"Provider: {provider_display}  |  Confidence: [bold]{result.confidence.upper()}[/bold]",
        title="[bold white]🤖 CorkScrew Analysis[/bold white]",
        subtitle="[dim]Terraform Synthetic Network Detector[/dim]",
        box=box.DOUBLE,
    ))

    # Category breakdown table
    console.print()
    table = Table(
        title="Category Breakdown",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Category", style="white")
    table.add_column("Score", justify="center")
    table.add_column("Flags", justify="center")
    table.add_column("Top Concern", style="dim")

    for cat in sorted(result.categories, key=lambda c: c.normalized_score, reverse=True):
        cat_color = get_score_color(cat.normalized_score)
        top_flag = cat.flags[0].name if cat.flags else "-"
        table.add_row(
            cat.name,
            f"[{cat_color}]{cat.normalized_score:.0f}%[/{cat_color}]",
            str(len(cat.flags)),
            top_flag[:40] + "..." if len(top_flag) > 40 else top_flag,
        )

    console.print(table)

    # Detailed flags
    if verbose:
        console.print()
        console.print("[bold]Detailed Flags:[/bold]")
        console.print()

        for cat in result.categories:
            if not cat.flags:
                continue

            console.print(f"[bold cyan]{cat.name}[/bold cyan]")
            for flag in cat.flags:
                console.print(f"  {get_severity_indicator(flag.severity)} [white]{flag.name}[/white]")
                console.print(f"     [dim]{flag.description}[/dim]")
                if flag.evidence:
                    for ev in flag.evidence[:3]:
                        console.print(f"     [dim italic]→ {ev}[/dim italic]")
            console.print()

    # Summary
    console.print()
    console.print(Panel(
        result.summary,
        title="[bold]Summary[/bold]",
        box=box.ROUNDED,
        padding=(1, 2),
    ))


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-v", "--verbose", is_flag=True, help="Show detailed flag information")
@click.option("-j", "--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("-q", "--quiet", is_flag=True, help="Only output the score (for scripting)")
def main(path: str, verbose: bool, output_json: bool, quiet: bool) -> None:
    """
    🤖 CorkScrew - Terraform Synthetic Network Detector

    Analyzes Terraform configurations to detect if they represent
    synthetic/honeypot infrastructure vs organic, production systems.

    Supports AWS and GCP resources with automatic provider detection.

    PATH can be a single .tf file or a directory containing .tf files.

    \b
    Score Interpretation:
      75-100: Highly likely synthetic/honeypot
      50-74:  Probable synthetic
      30-49:  Suspicious - mixed signals
      0-29:   Likely organic
    """
    target = Path(path)
    analyzer = TerraformAnalyzer()

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            if not quiet and not output_json:
                progress.add_task("Analyzing Terraform configuration...", total=None)

            if target.is_dir():
                analyzer.parse_directory(target)
            else:
                analyzer.parse_file(target)

            result = analyzer.analyze()

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1) from e

    # Output based on format
    if quiet:
        print(f"{result.synthetic_score:.1f}")
    elif output_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        render_result(result, verbose)


if __name__ == "__main__":
    main()
