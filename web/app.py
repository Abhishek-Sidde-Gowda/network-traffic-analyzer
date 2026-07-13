"""Flask web dashboard for Network Traffic Analyzer."""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import threading
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

UPLOAD_DIR = Path(__file__).parent.parent / "exports" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTS = {".pcap", ".pcapng"}


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB

    # ── routes ───────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/analyse", methods=["POST"])
    def api_analyse():
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        f = request.files["file"]
        if not f.filename:
            return jsonify({"error": "Empty filename"}), 400
        ext = Path(f.filename).suffix.lower()
        if ext not in ALLOWED_EXTS:
            return jsonify({"error": f"Unsupported file type: {ext}"}), 400

        fname = secure_filename(f.filename)
        save_path = UPLOAD_DIR / fname
        f.save(str(save_path))

        threshold = float(request.form.get("threshold", 0.6))
        contamination = float(request.form.get("contamination", 0.05))

        try:
            from core.engine import analyse_pcap
            result = analyse_pcap(
                save_path, contamination=contamination,
                anomaly_threshold=threshold,
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        # Build JSON response
        alerts_json = [
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
        ]

        top_anomalous = sorted(
            [r for r in result.flow_records if r.get("anomaly_label") == "ANOMALOUS"],
            key=lambda x: x.get("anomaly_score", 0), reverse=True
        )[:50]

        # Protocol distribution
        proto_counts: dict = {}
        for r in result.flow_records:
            p = r.get("protocol", "OTHER")
            proto_counts[p] = proto_counts.get(p, 0) + 1

        # Top talkers by bytes
        talker_map: dict = {}
        for r in result.flow_records:
            ip = r.get("src_ip", "")
            talker_map[ip] = talker_map.get(ip, 0) + r.get("total_bytes", 0)
        top_talkers = sorted(talker_map.items(), key=lambda x: x[1], reverse=True)[:10]

        # Top destination ports by flow count
        port_map: dict = {}
        for r in result.flow_records:
            port = r.get("dst_port", 0)
            port_map[port] = port_map.get(port, 0) + 1
        top_ports = sorted(port_map.items(), key=lambda x: x[1], reverse=True)[:15]

        # Traffic timeline — flows bucketed by minute
        from datetime import datetime
        timeline_map: dict = {}
        for r in result.flow_records:
            ts = r.get("start_time", 0)
            if ts:
                bucket = datetime.fromtimestamp(ts).strftime("%H:%M")
                timeline_map[bucket] = timeline_map.get(bucket, 0) + 1
        timeline = [{"time": k, "flows": v} for k, v in sorted(timeline_map.items())]

        # Risk scoring
        from detection.risk_scorer import score_all
        scored_flows = score_all(result.flow_records, result.alerts)
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in scored_flows:
            lvl = r.get("risk_level", "LOW")
            risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

        return jsonify({
            "summary": {
                "source": Path(result.source).name,
                "total_packets": result.total_packets,
                "total_flows": result.total_flows,
                "anomalous_flows": result.anomalous_flows,
                "alert_count": len(result.alerts),
                "anomaly_pct": round(result.anomalous_flows / max(result.total_flows, 1) * 100, 1),
            },
            "alerts": alerts_json,
            "top_anomalous_flows": top_anomalous,
            "protocol_distribution": proto_counts,
            "top_talkers": [{"ip": ip, "bytes": b} for ip, b in top_talkers],
            "top_ports": [{"port": p, "flows": c} for p, c in top_ports],
            "timeline": timeline,
            "risk_counts": risk_counts,
        })

    @app.route("/api/export/csv", methods=["POST"])
    def export_csv():
        data = request.get_json()
        flows = data.get("flows", [])
        if not flows:
            return jsonify({"error": "No flows"}), 400
        import pandas as pd, io
        df = pd.DataFrame(flows)
        buf = io.StringIO()
        df.to_csv(buf, index=False)
        buf.seek(0)
        from flask import Response
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=nta_flows.csv"},
        )

    return app
