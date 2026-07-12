"""
Export analysis results to PDF, CSV, and JSON.
"""
from __future__ import annotations

import json
import csv
from pathlib import Path
from datetime import datetime
from dataclasses import asdict


def export_json(result, path: str | Path) -> None:
    path = Path(path)
    data = {
        "generated_at": datetime.now().isoformat(),
        "source": result.source,
        "summary": {
            "total_packets": result.total_packets,
            "total_flows": result.total_flows,
            "anomalous_flows": result.anomalous_flows,
            "alert_count": len(result.alerts),
        },
        "alerts": [
            {
                "rule": a.rule_name,
                "severity": a.severity,
                "description": a.description,
                "src_ip": a.flow.get("src_ip"),
                "dst_ip": a.flow.get("dst_ip"),
                "dst_port": a.flow.get("dst_port"),
                "indicators": a.indicators,
            }
            for a in result.alerts
        ],
        "flows": result.flow_records,
    }
    path.write_text(json.dumps(data, indent=2, default=str))


def export_csv(result, path: str | Path) -> None:
    path = Path(path)
    if not result.flow_records:
        return
    fieldnames = list(result.flow_records[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(result.flow_records)


def export_pdf(result, path: str | Path) -> None:
    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether,
        )
    except ImportError:
        raise RuntimeError("reportlab not installed: pip install reportlab")

    path = Path(path)
    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle("title", parent=styles["Title"],
                                 textColor=colors.HexColor("#00d4ff"), fontSize=20)
    story.append(Paragraph("Network Traffic Analysis Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Source: {Path(result.source).name}",
        styles["Normal"]
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e2d40")))
    story.append(Spacer(1, 12))

    # Summary table
    summary_data = [
        ["Metric", "Value"],
        ["Total Packets", f"{result.total_packets:,}"],
        ["Total Flows", f"{result.total_flows:,}"],
        ["Anomalous Flows", f"{result.anomalous_flows:,}"],
        ["Alerts Triggered", f"{len(result.alerts)}"],
        ["Anomaly Rate", f"{result.anomalous_flows / max(result.total_flows, 1) * 100:.1f}%"],
    ]
    t = Table(summary_data, colWidths=[8*cm, 8*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00d4ff")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e2d40")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#111827"), colors.HexColor("#1a2035")]),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    # Alerts
    if result.alerts:
        story.append(Paragraph("Security Alerts", styles["Heading2"]))
        sev_colors = {
            "CRITICAL": colors.HexColor("#ef4444"),
            "HIGH": colors.HexColor("#f59e0b"),
            "MEDIUM": colors.HexColor("#3b82f6"),
            "LOW": colors.HexColor("#10b981"),
        }
        alert_data = [["Severity", "Rule", "Src IP", "Dst IP", "Port", "Description"]]
        for a in sorted(result.alerts, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity)):
            alert_data.append([
                a.severity, a.rule_name.replace("_", " ").title(),
                a.flow.get("src_ip", ""), a.flow.get("dst_ip", ""),
                str(a.flow.get("dst_port", "")),
                a.description[:55] + ("…" if len(a.description) > 55 else ""),
            ])
        at = Table(alert_data, colWidths=[2*cm, 3*cm, 3*cm, 3*cm, 1.5*cm, None], repeatRows=1)
        at.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2d40")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e2d40")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#111827"), colors.HexColor("#1a2035")]),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#e2e8f0")),
        ]))
        story.append(at)
        story.append(Spacer(1, 16))

    # Top anomalous flows
    anomalous = sorted(
        [f for f in result.flow_records if f.get("anomaly_label") == "ANOMALOUS"],
        key=lambda x: x.get("anomaly_score", 0), reverse=True
    )[:25]

    if anomalous:
        story.append(Paragraph("Top Anomalous Flows", styles["Heading2"]))
        flow_data = [["Score", "Src IP", "Dst IP", "Port", "Proto", "Bytes", "Pkt/s"]]
        for f in anomalous:
            flow_data.append([
                f"{f.get('anomaly_score', 0):.3f}",
                f.get("src_ip", ""), f.get("dst_ip", ""),
                str(f.get("dst_port", "")), f.get("protocol", ""),
                f"{f.get('total_bytes', 0):,}",
                f"{f.get('packets_per_second', 0):.1f}",
            ])
        ft = Table(flow_data, colWidths=[1.5*cm, 4*cm, 4*cm, 1.5*cm, 1.5*cm, 2.5*cm, 2*cm], repeatRows=1)
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2d40")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e2d40")),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#111827"), colors.HexColor("#1a2035")]),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#e2e8f0")),
        ]))
        story.append(ft)

    doc.build(story)
