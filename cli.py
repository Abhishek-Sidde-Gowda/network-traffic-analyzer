#!/usr/bin/env python3
"""
Network Traffic Analyzer — CLI
Usage:
    python cli.py analyse --file sample_data/sample_traffic.pcap
    python cli.py analyse --file traffic.pcap --threshold 0.5 --export report.pdf
    python cli.py serve              # launch web dashboard
    python cli.py generate-sample   # create sample_data/sample_traffic.pcap
"""
from __future__ import annotations

import sys
import os

# allow running from project root
sys.path.insert(0, os.path.dirname(__file__))

import click
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from rich.text import Text

console = Console()


# ─────────────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """Network Traffic Analyzer — ML-powered pcap analysis & intrusion detection."""


# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--file", "-f", "pcap_file", required=True,
              type=click.Path(exists=True), help="Path to .pcap or .pcapng file")
@click.option("--threshold", "-t", default=0.6, show_default=True,
              help="Anomaly score threshold (0-1). Higher = stricter.")
@click.option("--contamination", "-c", default=0.05, show_default=True,
              help="Expected fraction of anomalies (IsolationForest)")
@click.option("--top", "-n", default=20, show_default=True,
              help="Number of top anomalous flows to display")
@click.option("--export", "-e", default=None,
              help="Export report: report.pdf or report.csv")
def analyse(pcap_file, threshold, contamination, top, export):
    """Analyse a pcap file: flow extraction → ML scoring → alert generation."""
    from core.engine import analyse_pcap

    console.print(Panel.fit(
        f"[bold cyan]Network Traffic Analyzer[/bold cyan]\n"
        f"File: [yellow]{pcap_file}[/yellow] | Threshold: {threshold}",
        title="[bold green]NTA[/bold green]",
        border_style="green",
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
    ) as progress:
        t = progress.add_task("Parsing packets…", total=None)
        result = analyse_pcap(
            pcap_file,
            contamination=contamination,
            anomaly_threshold=threshold,
        )
        progress.update(t, description="[green]Done!", total=1, completed=1)

    # ── Summary panel ────────────────────────────────────────────────────────
    anomaly_pct = (result.anomalous_flows / max(result.total_flows, 1)) * 100
    summary = (
        f"[bold]Packets:[/bold]  {result.total_packets:,}\n"
        f"[bold]Flows:[/bold]    {result.total_flows:,}\n"
        f"[bold]Anomalous:[/bold][red] {result.anomalous_flows:,} ({anomaly_pct:.1f}%)[/red]\n"
        f"[bold]Alerts:[/bold]   [yellow]{len(result.alerts)}[/yellow]"
    )
    console.print(Panel(summary, title="Summary", border_style="blue"))

    # ── Alerts table ─────────────────────────────────────────────────────────
    if result.alerts:
        tbl = Table(title="Signature-Based Alerts", box=box.SIMPLE_HEAVY,
                    header_style="bold magenta")
        tbl.add_column("Severity", style="bold")
        tbl.add_column("Rule")
        tbl.add_column("Src IP")
        tbl.add_column("Dst IP")
        tbl.add_column("Port")
        tbl.add_column("Description")

        sev_colors = {"CRITICAL": "red", "HIGH": "orange3",
                      "MEDIUM": "yellow", "LOW": "green"}
        for a in sorted(result.alerts, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity)):
            col = sev_colors.get(a.severity, "white")
            tbl.add_row(
                f"[{col}]{a.severity}[/{col}]",
                a.rule_name,
                a.flow.get("src_ip", ""),
                a.flow.get("dst_ip", ""),
                str(a.flow.get("dst_port", "")),
                a.description,
            )
        console.print(tbl)

    # ── Top anomalous flows ───────────────────────────────────────────────────
    scored = sorted(result.flow_records, key=lambda x: x.get("anomaly_score", 0), reverse=True)
    top_flows = [f for f in scored if f.get("anomaly_label") == "ANOMALOUS"][:top]

    if top_flows:
        ftbl = Table(title=f"Top {len(top_flows)} Anomalous Flows", box=box.MINIMAL_DOUBLE_HEAD,
                     header_style="bold red")
        for col in ("Score", "Src IP", "Dst IP", "Dst Port", "Proto", "Bytes", "Pkt/s", "Flags"):
            ftbl.add_column(col)
        for f in top_flows:
            score = f.get("anomaly_score", 0)
            score_str = f"[red]{score:.3f}[/red]" if score > 0.8 else f"[yellow]{score:.3f}[/yellow]"
            flag_parts = []
            for flag in ("SYN", "ACK", "RST", "FIN", "PSH"):
                key = f"{flag.lower()}_ratio"
                if f.get(key, 0) > 0.5:
                    flag_parts.append(flag)
            ftbl.add_row(
                score_str,
                f.get("src_ip", ""),
                f.get("dst_ip", ""),
                str(f.get("dst_port", "")),
                f.get("protocol", ""),
                f"{f.get('total_bytes', 0):,}",
                f"{f.get('packets_per_second', 0):.1f}",
                ",".join(flag_parts) or "-",
            )
        console.print(ftbl)
    else:
        console.print("[green]No anomalous flows detected above threshold.[/green]")

    # ── Export ───────────────────────────────────────────────────────────────
    if export:
        _do_export(result, export)


def _do_export(result, path: str):
    p = Path(path)
    if p.suffix.lower() == ".csv":
        import pandas as pd
        pd.DataFrame(result.flow_records).to_csv(p, index=False)
        console.print(f"[green]CSV exported → {p}[/green]")
    elif p.suffix.lower() == ".pdf":
        _export_pdf(result, p)
    else:
        console.print(f"[red]Unknown export format: {p.suffix}[/red]")


def _export_pdf(result, path: Path):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors

        doc = SimpleDocTemplate(str(path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("Network Traffic Analysis Report", styles["Title"]))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Source: {result.source}", styles["Normal"]))
        story.append(Paragraph(f"Total Packets: {result.total_packets:,}", styles["Normal"]))
        story.append(Paragraph(f"Total Flows: {result.total_flows:,}", styles["Normal"]))
        story.append(Paragraph(f"Anomalous Flows: {result.anomalous_flows:,}", styles["Normal"]))
        story.append(Paragraph(f"Alerts Triggered: {len(result.alerts)}", styles["Normal"]))
        story.append(Spacer(1, 12))

        if result.alerts:
            story.append(Paragraph("Alerts", styles["Heading2"]))
            tdata = [["Severity", "Rule", "Src IP", "Dst IP", "Port", "Description"]]
            for a in result.alerts:
                tdata.append([
                    a.severity, a.rule_name,
                    a.flow.get("src_ip", ""), a.flow.get("dst_ip", ""),
                    str(a.flow.get("dst_port", "")), a.description[:60],
                ])
            t = Table(tdata, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(t)

        doc.build(story)
        console.print(f"[green]PDF report exported → {path}[/green]")
    except ImportError:
        console.print("[red]reportlab not installed. pip install reportlab[/red]")


# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=5000, show_default=True)
@click.option("--debug", is_flag=True, default=False)
def serve(host, port, debug):
    """Launch the web dashboard."""
    from web.app import create_app
    app = create_app()
    console.print(f"[bold green]Dashboard → http://{host}:{port}[/bold green]")
    app.run(host=host, port=port, debug=debug)


# ─────────────────────────────────────────────────────────────────────────────

@cli.command("generate-sample")
def generate_sample():
    """Generate sample_data/sample_traffic.pcap with synthetic attack traffic."""
    console.print("[cyan]Generating sample pcap…[/cyan]")
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location(
        "generate",
        Path(__file__).parent / "sample_data" / "generate.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
