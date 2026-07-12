# Network Traffic Analyzer

ML-powered network traffic analyzer and intrusion detection system.  
Parses pcap files → aggregates flows → scores anomalies with an ensemble ML model → fires signature-based alerts.

---

## Features

| Capability | Detail |
|---|---|
| **Packet parsing** | dpkt (primary) + scapy fallback; supports .pcap and .pcapng |
| **Flow aggregation** | Bidirectional 5-tuple flows with inactivity timeout |
| **ML anomaly detection** | IsolationForest + LOF ensemble, normalised score [0,1] |
| **Signature rules** | Port scan, SYN flood, DNS tunnelling, data exfiltration, ICMP flood, brute force, C2 beaconing |
| **Web dashboard** | Dark-theme Flask app with Plotly charts, drag-and-drop upload, CSV export |
| **CLI** | Rich terminal output, PDF/CSV report export |
| **Live capture** | scapy-based streaming capture from any network interface |

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Generate sample traffic (port scan + SYN flood + DNS tunnel + C2 beacon)
python3 sample_data/generate.py

# Run CLI analysis
python3 cli.py analyse --file sample_data/sample_traffic.pcap

# Export PDF report
python3 cli.py analyse --file sample_data/sample_traffic.pcap --export report.pdf

# Launch web dashboard
python3 cli.py serve
# → open http://127.0.0.1:5000
```

---

## Architecture

```
network-traffic-analyzer/
├── core/
│   ├── packet_parser.py      # Raw pcap → Packet objects (dpkt/scapy)
│   ├── flow_aggregator.py    # Packets → bidirectional Flow objects + stats
│   ├── live_capture.py       # Live interface capture (scapy, needs root)
│   └── engine.py             # High-level pipeline entry point
├── ml/
│   ├── feature_extractor.py  # Flow stats → 20-feature ML matrix
│   └── anomaly_detector.py   # IsolationForest + LOF ensemble scorer
├── detection/
│   └── rules.py              # 7 signature rules → Alert objects
├── web/
│   ├── app.py                # Flask API + file upload endpoint
│   └── templates/index.html  # Dark dashboard (Plotly charts, no framework)
├── exports/
│   └── reporter.py           # PDF (reportlab) / CSV / JSON exporters
├── sample_data/
│   └── generate.py           # Synthetic pcap generator (1350 packets)
├── tests/
│   └── test_core.py          # 15 unit tests (flow, ML, rules)
└── cli.py                    # Click CLI (analyse / serve / generate-sample)
```

---

## ML Pipeline

1. **Feature extraction** — 20 numeric features per flow including:  
   `duration`, `bytes/s`, `packets/s`, `syn_ratio`, `rst_ratio`, `payload_ratio`, `log_bytes`, `unique_ttls` …

2. **IsolationForest** — unsupervised, trained on the analysed batch itself.  
   Contamination parameter controls expected anomaly fraction (default 5%).

3. **LOF** — Local Outlier Factor as a second opinion on the same batch.

4. **Ensemble score** — `0.7 × IF_score + 0.3 × LOF_score`, normalised to [0,1].

5. **Threshold** — Flows above threshold (default 0.6) labelled `ANOMALOUS`.

---

## Detection Rules

| Rule | Trigger |
|---|---|
| `port_scan` | SYN ratio > 70%, ACK ratio < 30% |
| `syn_flood` | > 500 pkt/s AND SYN ratio > 80% |
| `dns_tunnelling` | Port 53, avg packet > 400 B, sustained rate |
| `data_exfiltration` | > 50 MB to non-standard port |
| `icmp_flood` | ICMP > 200 pkt/s |
| `brute_force` | SSH/RDP/Telnet/VNC, RST ratio > 30% |
| `beaconing` | Long-duration flow, regular tiny packets (C2 pattern) |

---

## Tests

```bash
python3 -m pytest tests/ -v
# 15 passed
```

---

## Live Capture (requires root)

```python
from core.live_capture import LiveCapture
cap = LiveCapture(iface="en0", bpf_filter="tcp or udp")
cap.start()
for pkt in cap.stream(timeout=60):
    print(pkt.src_ip, pkt.dst_ip, pkt.protocol)
cap.stop()
```

---

## Dissertation Connection

This tool implements the same unsupervised anomaly detection approach used in the dissertation (ML-based intrusion detection on network flows). IsolationForest was selected as the primary model for its linear time complexity and strong performance on high-dimensional, mixed-distribution network feature spaces. The ensemble with LOF reduces false positives on borderline flows.
