"""CLI Interface for PhishTriage (scan, report, eval)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from phishtriage.pipeline import PhishTriagePipeline
from phishtriage.reporting import ReportGenerator
from phishtriage.storage import Storage

app = typer.Typer(
    name="phishtriage",
    help="PhishTriage: Automated Phishing & BEC Detection and Triage Pipeline",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to raw .eml file or directory containing .eml files"),
    rules: str = typer.Option("rules/detection_rules.yaml", "--rules", "-r", help="Path to YAML rules file"),
    blocklist: str = typer.Option("blocklist_hashes.txt", "--blocklist", "-b", help="Path to SHA256 hash blocklist"),
    db: str = typer.Option("phishtriage.db", "--db", help="Path to SQLite database"),
    markdown_out: Optional[str] = typer.Option(None, "--md-out", help="Save markdown report to specified path"),
    iocs_out: Optional[str] = typer.Option(None, "--iocs-out", help="Save IOCs JSON to specified path"),
) -> None:
    """Scan a raw .eml file or directory of .eml files and display findings."""
    pipeline = PhishTriagePipeline(rules_path=rules, blocklist_path=blocklist, db_path=db)
    target_path = Path(target)

    if not target_path.exists():
        console.print(f"[bold red]Error: Target '{target}' does not exist.[/bold red]")
        raise typer.Exit(code=1)

    files_to_scan = [target_path] if target_path.is_file() else list(target_path.glob("*.eml"))
    if not files_to_scan:
        console.print(f"[yellow]No .eml files found in '{target}'.[/yellow]")
        return

    table = Table(title=f"PhishTriage Scan Results ({len(files_to_scan)} files)")
    table.add_column("File / Incident ID", style="cyan")
    table.add_column("Subject", style="white")
    table.add_column("Sender", style="magenta")
    table.add_column("Score", justify="center")
    table.add_column("Verdict", justify="center")
    table.add_column("MITRE ATT&CK", style="yellow")

    reports = []
    for file in files_to_scan:
        report = pipeline.process_file(file)
        reports.append((file, report))

        verdict_color = "green" if report.verdict.value == "benign" else ("yellow" if report.verdict.value == "suspicious" else "bold red")
        table.add_row(
            f"{file.name}\n({report.incident_id})",
            report.email_subject[:30],
            report.sender[:30],
            f"{report.score}/100",
            f"[{verdict_color}]{report.verdict.value.upper()}[/{verdict_color}]",
            ", ".join(report.mitre_techniques) if report.mitre_techniques else "-",
        )

    console.print(table)

    # If single file scanned and output requested
    if len(reports) == 1:
        single_report = reports[0][1]
        if markdown_out:
            md_content = ReportGenerator.generate_markdown(single_report)
            Path(markdown_out).write_text(md_content, encoding="utf-8")
            console.print(f"[green]Markdown report written to {markdown_out}[/green]")
        if iocs_out:
            ioc_content = ReportGenerator.export_iocs_json(single_report)
            Path(iocs_out).write_text(ioc_content, encoding="utf-8")
            console.print(f"[green]IOCs exported to {iocs_out}[/green]")


@app.command()
def report(
    incident_id: str = typer.Argument(..., help="Incident ID to view (e.g. INC-XXXXXXXXXXXX)"),
    db: str = typer.Option("phishtriage.db", "--db", help="Path to SQLite database"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown or json"),
) -> None:
    """Retrieve and format an incident report from the local database."""
    storage = Storage(db_path=db)
    incident = storage.get_incident(incident_id)

    if not incident:
        console.print(f"[bold red]Incident '{incident_id}' not found in database.[/bold red]")
        raise typer.Exit(code=1)

    if format.lower() == "json":
        console.print(incident.model_dump_json(indent=2))
    else:
        console.print(ReportGenerator.generate_markdown(incident))


@app.command()
def eval(
    dataset_dir: str = typer.Option("data/synthetic_dataset", "--dataset", "-d", help="Directory of labeled dataset"),
    labels_file: str = typer.Option("data/synthetic_dataset/labels.json", "--labels", "-l", help="Dataset ground truth JSON"),
    rules: str = typer.Option("rules/detection_rules.yaml", "--rules", "-r", help="Path to YAML rules file"),
    blocklist: str = typer.Option("blocklist_hashes.txt", "--blocklist", "-b", help="Path to SHA256 hash blocklist"),
) -> None:
    """Evaluate pipeline precision, recall, F1, and confusion matrix against a labeled ground-truth dataset."""
    from phishtriage.eval import DatasetEvaluator

    evaluator = DatasetEvaluator(
        rules_path=rules,
        blocklist_path=blocklist,
        dataset_dir=dataset_dir,
        labels_file=labels_file,
    )
    evaluator.run_and_print()


if __name__ == "__main__":
    app()
