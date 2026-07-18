#!/usr/bin/env python3
"""Build a self-contained HTML dashboard (charts) from the JSON metrics
produced by analyze_logs.py.

Reads every reports/data/metrics_*.json file (one per day the analysis has
run) to build a trend-over-time chart, plus the most recent file for the
point-in-time breakdowns (top IPs, countries, ports, malware families).

Usage:
    python scripts/generate_dashboard.py                 # writes reports/dashboard.html
    python scripts/generate_dashboard.py --offline        # bundle plotly.js inline (~3-4MB, no internet needed to view)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.config import load_config, REPO_ROOT  # noqa: E402
from common.logging_utils import get_logger  # noqa: E402

logger = get_logger("generate_dashboard")


def load_all_metrics(data_dir: Path) -> list[dict]:
    files = sorted(data_dir.glob("metrics_*.json"))
    metrics = []
    for f in files:
        try:
            metrics.append(json.loads(f.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            logger.warning("Skipping unparseable metrics file: %s", f)
    return metrics


def build_timeline_figure(all_metrics: list[dict]) -> go.Figure:
    merged: defaultdict[str, int] = defaultdict(int)
    for m in all_metrics:
        for day, count in m.get("timeline_daily", {}).items():
            merged[day] += count
    days = sorted(merged.keys())
    counts = [merged[d] for d in days]

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=days, y=counts, mode="lines+markers", name="Events/day",
                              line=dict(color="#e35d5d")))
    fig.update_layout(title="Attack Volume Over Time", xaxis_title="Date", yaxis_title="Events",
                       template="plotly_dark")
    return fig


def build_bar_figure(pairs: list, title: str, x_title: str, top_n: int = 15) -> go.Figure:
    pairs = pairs[:top_n]
    labels = [str(p[0]) if isinstance(p, (list, tuple)) else str(p) for p in pairs]
    values = [p[1] if isinstance(p, (list, tuple)) else 0 for p in pairs]
    fig = go.Figure(go.Bar(x=labels, y=values, marker_color="#5da9e3"))
    fig.update_layout(title=title, xaxis_title=x_title, yaxis_title="Count", template="plotly_dark")
    return fig


def build_ip_bar_figure(top_ips: list[dict], top_n: int = 15) -> go.Figure:
    top_ips = top_ips[:top_n]
    labels = [f"{row['ip']} ({row['country']})" for row in top_ips]
    values = [row["count"] for row in top_ips]
    fig = go.Figure(go.Bar(x=labels, y=values, marker_color="#e3a75d"))
    fig.update_layout(title="Top Attacking IPs", xaxis_title="IP (Country)", yaxis_title="Events",
                       template="plotly_dark")
    return fig


def render_dashboard(all_metrics: list[dict], include_plotlyjs) -> str:
    if not all_metrics:
        return "<h1>No metrics available yet</h1><p>Run extract_logs.py then analyze_logs.py first.</p>"

    latest = all_metrics[-1]
    timeline_fig = build_timeline_figure(all_metrics)
    ip_fig = build_ip_bar_figure(latest.get("top_ips", []))
    country_fig = build_bar_figure(latest.get("top_countries", []), "Top Attacker Countries", "Country")
    port_fig = build_bar_figure(latest.get("top_ports", []), "Top Targeted Ports", "Port")
    malware_fig = build_bar_figure(latest.get("malware_families", []), "Malware Families Detected", "Family")
    webattack_fig = build_bar_figure(latest.get("web_attack_types", []), "Web Attack Types", "Attack Type")

    parts = [
        "<html><head><meta charset='utf-8'><title>T-Pot Honeypot Dashboard</title>",
        "<style>body{background:#111;color:#eee;font-family:sans-serif;margin:0;padding:20px;}",
        "h1{color:#e35d5d} .meta{color:#888;margin-bottom:20px} .chart{margin-bottom:40px}</style>",
        "</head><body>",
        "<h1>T-Pot Honeypot Dashboard</h1>",
        f"<div class='meta'>Latest report: {latest.get('generated_at_utc')} | "
        f"Total events (latest run): {latest.get('total_events')} | "
        f"Unique attacker IPs (latest run): {latest.get('unique_attacker_ips')} | "
        f"Reports aggregated: {len(all_metrics)}</div>",
    ]

    figs = [timeline_fig, ip_fig, country_fig, port_fig, webattack_fig, malware_fig]
    for i, fig in enumerate(figs):
        this_include = include_plotlyjs if i == 0 else False  # only need the JS bundle once
        parts.append("<div class='chart'>")
        parts.append(fig.to_html(full_html=False, include_plotlyjs=this_include))
        parts.append("</div>")

    parts.append("<p style='color:#666'>Generated automatically by scripts/generate_dashboard.py</p>")
    parts.append("</body></html>")
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=None)
    parser.add_argument("--offline", action="store_true", help="Bundle plotly.js inline instead of loading from CDN")
    parser.add_argument("--output", default=None, help="Output HTML path (default: <reports_dir>/dashboard.html)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    reports_dir = REPO_ROOT / cfg.reports_dir
    data_dir = reports_dir / "data"

    all_metrics = load_all_metrics(data_dir)
    if not all_metrics:
        logger.warning("No metrics files found under %s - run analyze_logs.py first.", data_dir)

    include_plotlyjs = True if args.offline else "cdn"
    html = render_dashboard(all_metrics, include_plotlyjs)

    output_path = Path(args.output) if args.output else reports_dir / "dashboard.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    logger.info("Dashboard written to %s", output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
