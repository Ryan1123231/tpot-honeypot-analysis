"""Defensive parsers for T-Pot's various log formats.

T-Pot's honeypot containers each log slightly differently, and exact field
names can shift between T-Pot releases. Rather than hard-fail on an
unexpected schema, every parser here normalizes into a common `Event`
namedtuple using a list of acceptable field-name aliases per attribute, and
silently skips lines it can't make sense of (counting them so callers can
log a summary).

IMPORTANT: field alias lists below were set from T-Pot's documented log
directory layout, not from a live capture (no attack traffic has hit the
honeypot yet as of writing this). Run `python scripts/analyze_logs.py
--dump-sample` after the first real extraction and compare against these
lists - see docs/METHODOLOGY.md "Calibrating the parser" section.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("log_parsing")

# Ordered lists of acceptable keys per logical field, most-likely-first.
# client_ip/server_ip/client_port/server_port confirmed against real p0f
# output (p0f labels the honeypot side "server" and the remote side
# "client" regardless of who initiated the connection).
SRC_IP_KEYS = ["src_ip", "source_ip", "srcip", "peer_ip", "ip", "remote_ip", "client_ip"]
DEST_PORT_KEYS = ["dest_port", "dst_port", "target_port", "port", "dport", "server_port"]
SRC_PORT_KEYS = ["src_port", "source_port", "sport", "client_port"]
TIMESTAMP_KEYS = ["timestamp", "@timestamp", "time", "datetime", "date"]
PROTOCOL_KEYS = ["protocol", "proto", "service", "honeypot", "app"]
USERNAME_KEYS = ["username", "user", "login"]
PASSWORD_KEYS = ["password", "pass", "passwd"]
URL_PATH_KEYS = ["path", "url", "uri", "request_url", "request"]
EVENT_TYPE_KEYS = ["eventid", "event_type", "event", "type"]


@dataclass
class Event:
    source: str  # which honeypot/tool produced this (dir name it came from)
    raw: dict[str, Any] = field(repr=False)
    src_ip: str | None = None
    src_port: int | None = None
    dest_port: int | None = None
    timestamp: str | None = None
    protocol: str | None = None
    username: str | None = None
    password: str | None = None
    url_path: str | None = None
    event_type: str | None = None
    alert_signature: str | None = None
    alert_category: str | None = None


def _first_present(d: dict[str, Any], keys: list[str]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _to_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def iter_json_lines(path: Path) -> Iterator[dict[str, Any]]:
    """Yield parsed JSON objects from a JSON-lines file, skipping bad lines."""
    skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
                else:
                    skipped += 1
            except json.JSONDecodeError:
                skipped += 1
    if skipped:
        logger.warning("%s: skipped %d unparseable/non-object lines", path, skipped)


def normalize_generic(raw: dict[str, Any], source: str) -> Event:
    """Normalize a generic honeypot JSON record (e.g. the 'honeypots' container)."""
    return Event(
        source=source,
        raw=raw,
        src_ip=_first_present(raw, SRC_IP_KEYS),
        src_port=_to_int(_first_present(raw, SRC_PORT_KEYS)),
        dest_port=_to_int(_first_present(raw, DEST_PORT_KEYS)),
        timestamp=_first_present(raw, TIMESTAMP_KEYS),
        protocol=_first_present(raw, PROTOCOL_KEYS),
        username=_first_present(raw, USERNAME_KEYS),
        password=_first_present(raw, PASSWORD_KEYS),
        url_path=_first_present(raw, URL_PATH_KEYS),
        event_type=_first_present(raw, EVENT_TYPE_KEYS),
    )


def normalize_suricata(raw: dict[str, Any]) -> Event | None:
    """Normalize a Suricata EVE JSON record. Schema here is Suricata's stable,
    well-documented EVE format, unlike the honeypot-specific logs above."""
    event_type = raw.get("event_type")
    ev = Event(
        source="suricata",
        raw=raw,
        src_ip=raw.get("src_ip"),
        src_port=_to_int(raw.get("src_port")),
        dest_port=_to_int(raw.get("dest_port")),
        timestamp=raw.get("timestamp"),
        protocol=raw.get("proto"),
        event_type=event_type,
    )
    if event_type == "alert":
        alert = raw.get("alert", {}) or {}
        ev.alert_signature = alert.get("signature")
        ev.alert_category = alert.get("category")
    return ev


def load_events(source_dir: Path, source_name: str) -> tuple[list[Event], int]:
    """Load every *.log/*.json file under source_dir, normalizing based on source_name."""
    events: list[Event] = []
    total_skipped = 0
    if not source_dir.exists():
        logger.warning("Log directory does not exist, skipping: %s", source_dir)
        return events, total_skipped

    files = list(source_dir.rglob("*.log")) + list(source_dir.rglob("*.json"))
    if not files:
        logger.warning("No .log/.json files found under %s", source_dir)
        return events, total_skipped

    for file_path in files:
        for raw in iter_json_lines(file_path):
            if source_name == "suricata":
                ev = normalize_suricata(raw)
            else:
                ev = normalize_generic(raw, source_name)
            if ev is not None:
                if ev.src_ip is None and ev.event_type not in ("flow", "stats"):
                    total_skipped += 1
                    continue
                events.append(ev)
    logger.info("Loaded %d events from %s (%s), %d records skipped (no src_ip)", len(events), source_dir, source_name, total_skipped)
    return events, total_skipped
