#!/usr/bin/env python3
"""Parse extracted T-Pot logs and produce attack metrics + a Markdown report.

Reads the most recent extraction under data/raw/ (or --logs-dir), computes:
  - top attacking IPs + frequency
  - countries/geolocation of attackers
  - attack types & patterns (brute force, port scanning, web attacks)
  - ports targeted
  - malware families (from Suricata alert signatures)
  - timeline of attacks (hourly + daily buckets)

...and writes:
  - reports/data/metrics_<UTC date>.json   (machine-readable, used by the dashboard)
  - reports/report_<UTC date>.md           (human-readable summary)
  - reports/LATEST.md                      (copy of the most recent report)

Usage:
    python scripts/analyze_logs.py                       # analyze latest extraction
    python scripts/analyze_logs.py --logs-dir data/raw/20260717T120000Z
    python scripts/analyze_logs.py --dump-sample          # print raw sample lines per source, then exit
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from dateutil import parser as dateparser

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.config import load_config, REPO_ROOT  # noqa: E402
from common.geolocation import resolve_many  # noqa: E402
from common.log_parsing import Event, load_events  # noqa: E402
from common.logging_utils import get_logger  # noqa: E402

logger = get_logger("analyze_logs")

SOURCES = ["honeypots", "suricata", "p0f", "fatt"]
TOP_N = 20
BRUTE_FORCE_THRESHOLD = 5       # auth attempts from one IP -> flag as brute force
PORT_SCAN_THRESHOLD = 5         # distinct dest ports from one IP -> flag as scan
AUTH_EVENT_MARKERS = {"login", "auth", "cowrie.login.failed", "cowrie.login.success"}

# Regex patterns matched against Suricata alert signatures / honeypot request
# paths to tag known malware families and common web-exploit attempts.
# Not exhaustive - extend as you observe real traffic (see docs/METHODOLOGY.md).
MALWARE_FAMILY_PATTERNS = {
    "Mirai": re.compile(r"\bmirai\b", re.I),
    "Gafgyt/Bashlite": re.compile(r"\b(gafgyt|bashlite|lizkebab|qbot)\b", re.I),
    "Emotet": re.compile(r"\bemotet\b", re.I),
    "TrickBot": re.compile(r"\btrickbot\b", re.I),
    "Qakbot": re.compile(r"\bqakbot\b", re.I),
    "Dridex": re.compile(r"\bdridex\b", re.I),
    "Cobalt Strike": re.compile(r"\bcobalt\s*strike\b", re.I),
    "Metasploit": re.compile(r"\bmetasploit\b", re.I),
    "WannaCry": re.compile(r"\bwannacry\b", re.I),
    "Log4Shell/Log4j": re.compile(r"\b(log4shell|log4j|jndi:ldap|jndi:rmi)\b", re.I),
    "Andromeda": re.compile(r"\bandromeda\b", re.I),
    "njRAT": re.compile(r"\bnjrat\b", re.I),
    "AsyncRAT": re.compile(r"\basyncrat\b", re.I),
    "Redline Stealer": re.compile(r"\bredline\b", re.I),
    "XMRig/Cryptominer": re.compile(r"\b(xmrig|cryptominer|coinminer|monero.?mining)\b", re.I),
}

WEB_ATTACK_PATTERNS = {
    "SQL Injection": re.compile(r"(union\s+select|or\s+1=1|sleep\(|information_schema)", re.I),
    "Path Traversal": re.compile(r"(\.\./\.\./|%2e%2e%2f)", re.I),
    "Log4Shell Probe": re.compile(r"\$\{jndi:", re.I),
    "WordPress Probe": re.compile(r"/wp-(login|admin|content|includes)", re.I),
    "Webshell Upload/Access": re.compile(r"\.(php|jsp|asp)x?\?.*=|/shell\.|/cmd\.", re.I),
    "Generic RCE Attempt": re.compile(r"(;|\|)\s*(wget|curl|nc|bash|sh)\s", re.I),
}


def find_latest_logs_dir() -> Path | None:
    raw_dir = REPO_ROOT / "data" / "raw"
    pointer = raw_dir / "LATEST.txt"
    if pointer.exists():
        candidate = raw_dir / pointer.read_text(encoding="utf-8").strip()
        if candidate.exists():
            return candidate
    subdirs = sorted([p for p in raw_dir.glob("*") if p.is_dir()])
    return subdirs[-1] if subdirs else None


def dump_sample(logs_dir: Path, n: int = 5) -> None:
    for source in SOURCES:
        source_dir = logs_dir / source
        files = list(source_dir.rglob("*.log")) + list(source_dir.rglob("*.json")) if source_dir.exists() else []
        print(f"\n=== {source} ({len(files)} files) ===")
        shown = 0
        for f in files:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    print(f"  [{f.name}] {line[:300]}")
                    shown += 1
                    if shown >= n:
                        break
            if shown >= n:
                break
        if shown == 0:
            print("  (no data)")


def parse_timestamp(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        return dateparser.parse(ts).timestamp()
    except (ValueError, OverflowError, TypeError):
        return None


def compute_metrics(events: list[Event], geo_cache_path: Path) -> dict[str, Any]:
    ip_counter: Counter[str] = Counter()
    port_counter: Counter[int] = Counter()
    source_counter: Counter[str] = Counter()
    auth_attempts_by_ip: Counter[str] = Counter()
    ports_by_ip: defaultdict[str, set[int]] = defaultdict(set)
    malware_hits: Counter[str] = Counter()
    web_attack_hits: Counter[str] = Counter()
    hourly_timeline: Counter[str] = Counter()
    daily_timeline: Counter[str] = Counter()
    credential_pairs: Counter[tuple[str, str]] = Counter()

    for ev in events:
        source_counter[ev.source] += 1
        if ev.src_ip:
            ip_counter[ev.src_ip] += 1
        if ev.dest_port:
            port_counter[ev.dest_port] += 1
        if ev.src_ip and ev.dest_port:
            ports_by_ip[ev.src_ip].add(ev.dest_port)

        if ev.src_ip and (ev.event_type in AUTH_EVENT_MARKERS or (ev.username is not None or ev.password is not None)):
            auth_attempts_by_ip[ev.src_ip] += 1
            if ev.username or ev.password:
                credential_pairs[(ev.username or "", ev.password or "")] += 1

        if ev.alert_signature:
            for family, pattern in MALWARE_FAMILY_PATTERNS.items():
                if pattern.search(ev.alert_signature):
                    malware_hits[family] += 1
            for attack_type, pattern in WEB_ATTACK_PATTERNS.items():
                if pattern.search(ev.alert_signature):
                    web_attack_hits[attack_type] += 1

        if ev.url_path:
            for attack_type, pattern in WEB_ATTACK_PATTERNS.items():
                if pattern.search(ev.url_path):
                    web_attack_hits[attack_type] += 1

        ts = parse_timestamp(ev.timestamp)
        if ts:
            hourly_timeline[time.strftime("%Y-%m-%d %H:00", time.gmtime(ts))] += 1
            daily_timeline[time.strftime("%Y-%m-%d", time.gmtime(ts))] += 1

    brute_force_ips = {ip: count for ip, count in auth_attempts_by_ip.items() if count >= BRUTE_FORCE_THRESHOLD}
    port_scan_ips = {ip: len(ports) for ip, ports in ports_by_ip.items() if len(ports) >= PORT_SCAN_THRESHOLD}

    unique_ips = list(ip_counter.keys())
    geo = resolve_many(unique_ips, geo_cache_path) if unique_ips else {}
    country_counter: Counter[str] = Counter()
    for ip, count in ip_counter.items():
        country = geo.get(ip, {}).get("country") or "Unknown"
        country_counter[country] += count

    top_ips_with_geo = [
        {
            "ip": ip,
            "count": count,
            "country": geo.get(ip, {}).get("country", "Unknown"),
            "city": geo.get(ip, {}).get("city", ""),
            "org": geo.get(ip, {}).get("org", ""),
        }
        for ip, count in ip_counter.most_common(TOP_N)
    ]

    return {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_events": len(events),
        "events_by_source": dict(source_counter),
        "unique_attacker_ips": len(unique_ips),
        "top_ips": top_ips_with_geo,
        "top_countries": country_counter.most_common(TOP_N),
        "top_ports": port_counter.most_common(TOP_N),
        "brute_force_ips": dict(sorted(brute_force_ips.items(), key=lambda x: -x[1])[:TOP_N]),
        "port_scan_ips": dict(sorted(port_scan_ips.items(), key=lambda x: -x[1])[:TOP_N]),
        "malware_families": malware_hits.most_common(),
        "web_attack_types": web_attack_hits.most_common(),
        "top_credential_pairs": [
            {"username": u, "password": p, "count": c}
            for (u, p), c in credential_pairs.most_common(TOP_N)
        ],
        "timeline_hourly": dict(sorted(hourly_timeline.items())),
        "timeline_daily": dict(sorted(daily_timeline.items())),
    }


def render_markdown_report(metrics: dict[str, Any], logs_dir: Path) -> str:
    lines: list[str] = []
    lines.append(f"# T-Pot Honeypot Report - {metrics['generated_at_utc']}")
    lines.append("")
    lines.append(f"Source data: `{logs_dir.name}` &nbsp;|&nbsp; Total events analyzed: **{metrics['total_events']}** "
                  f"&nbsp;|&nbsp; Unique attacker IPs: **{metrics['unique_attacker_ips']}**")
    lines.append("")
    lines.append("Events by source: " + ", ".join(f"`{k}`: {v}" for k, v in metrics["events_by_source"].items()))
    lines.append("")

    lines.append("## Top Attacking IPs")
    if metrics["top_ips"]:
        lines.append("| IP | Events | Country | City | Org/ASN |")
        lines.append("|---|---:|---|---|---|")
        for row in metrics["top_ips"]:
            lines.append(f"| `{row['ip']}` | {row['count']} | {row['country']} | {row['city']} | {row['org']} |")
    else:
        lines.append("_No attacker IPs recorded yet._")
    lines.append("")

    lines.append("## Top Countries")
    if metrics["top_countries"]:
        lines.append("| Country | Events |")
        lines.append("|---|---:|")
        for country, count in metrics["top_countries"]:
            lines.append(f"| {country} | {count} |")
    else:
        lines.append("_No geolocation data yet._")
    lines.append("")

    lines.append("## Top Targeted Ports")
    if metrics["top_ports"]:
        lines.append("| Port | Events |")
        lines.append("|---|---:|")
        for port, count in metrics["top_ports"]:
            lines.append(f"| {port} | {count} |")
    else:
        lines.append("_No port data yet._")
    lines.append("")

    lines.append("## Attack Patterns")
    lines.append(f"**Likely brute-force sources** (>= {BRUTE_FORCE_THRESHOLD} auth attempts): "
                  f"{len(metrics['brute_force_ips'])}")
    if metrics["brute_force_ips"]:
        lines.append("")
        lines.append("| IP | Auth Attempts |")
        lines.append("|---|---:|")
        for ip, count in metrics["brute_force_ips"].items():
            lines.append(f"| `{ip}` | {count} |")
    lines.append("")
    lines.append(f"**Likely port-scan sources** (>= {PORT_SCAN_THRESHOLD} distinct ports touched): "
                  f"{len(metrics['port_scan_ips'])}")
    if metrics["port_scan_ips"]:
        lines.append("")
        lines.append("| IP | Distinct Ports |")
        lines.append("|---|---:|")
        for ip, count in metrics["port_scan_ips"].items():
            lines.append(f"| `{ip}` | {count} |")
    lines.append("")
    if metrics["web_attack_types"]:
        lines.append("**Web attack signatures matched:**")
        lines.append("")
        lines.append("| Attack Type | Matches |")
        lines.append("|---|---:|")
        for attack_type, count in metrics["web_attack_types"]:
            lines.append(f"| {attack_type} | {count} |")
        lines.append("")

    lines.append("## Malware Families Detected")
    lines.append("_Detected via Suricata alert signature matching - see docs/METHODOLOGY.md for caveats._")
    if metrics["malware_families"]:
        lines.append("")
        lines.append("| Family | Alerts |")
        lines.append("|---|---:|")
        for family, count in metrics["malware_families"]:
            lines.append(f"| {family} | {count} |")
    else:
        lines.append("")
        lines.append("_None detected in this period._")
    lines.append("")

    if metrics["top_credential_pairs"]:
        lines.append("## Top Credential Pairs Attempted")
        lines.append("| Username | Password | Attempts |")
        lines.append("|---|---|---:|")
        for row in metrics["top_credential_pairs"]:
            lines.append(f"| `{row['username']}` | `{row['password']}` | {row['count']} |")
        lines.append("")

    lines.append("## Timeline (daily)")
    if metrics["timeline_daily"]:
        lines.append("| Date | Events |")
        lines.append("|---|---:|")
        for day, count in metrics["timeline_daily"].items():
            lines.append(f"| {day} | {count} |")
    else:
        lines.append("_No timestamped events yet._")
    lines.append("")
    lines.append("---")
    lines.append("_Generated automatically by `scripts/analyze_logs.py`. "
                  "See `scripts/generate_dashboard.py` for a chart-based HTML view of this same data._")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=None)
    parser.add_argument("--logs-dir", default=None, help="Path to a specific data/raw/<timestamp> dir (default: latest)")
    parser.add_argument("--dump-sample", action="store_true", help="Print raw sample lines per source and exit (schema calibration)")
    args = parser.parse_args()

    cfg = load_config(args.config)

    logs_dir = Path(args.logs_dir) if args.logs_dir else find_latest_logs_dir()
    if logs_dir is None or not logs_dir.exists():
        logger.error("No extracted logs found under data/raw/. Run scripts/extract_logs.py first.")
        return 2
    logger.info("Analyzing logs from: %s", logs_dir)

    if args.dump_sample:
        dump_sample(logs_dir)
        return 0

    all_events: list[Event] = []
    for source in SOURCES:
        events, _skipped = load_events(logs_dir / source, source)
        all_events.extend(events)

    if not all_events:
        logger.warning("No events parsed from any source under %s - is the honeypot receiving traffic yet?", logs_dir)

    geo_cache_path = REPO_ROOT / cfg.geo_cache_path
    metrics = compute_metrics(all_events, geo_cache_path)

    reports_dir = REPO_ROOT / cfg.reports_dir
    data_dir = reports_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    date_tag = time.strftime("%Y-%m-%d", time.gmtime())
    metrics_path = data_dir / f"metrics_{date_tag}.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    logger.info("Wrote metrics: %s", metrics_path)

    report_md = render_markdown_report(metrics, logs_dir)
    report_path = reports_dir / f"report_{date_tag}.md"
    report_path.write_text(report_md, encoding="utf-8")
    (reports_dir / "LATEST.md").write_text(report_md, encoding="utf-8")
    logger.info("Wrote report: %s", report_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
