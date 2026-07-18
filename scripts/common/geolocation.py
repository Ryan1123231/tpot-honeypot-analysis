"""IP -> country/city lookups via ip-api.com's free batch endpoint, with a
local JSON cache so repeat runs don't re-query IPs we've already resolved.

ip-api.com's free tier: keyless, ~45 req/min for single lookups, and a batch
endpoint (POST /batch) accepting up to 100 IPs per call at ~15 calls/min -
plenty for a single-honeypot's daily/weekly unique-attacker volume. If you
outgrow it, swap this module for MaxMind GeoLite2 (mmdb file + geoip2
package) - the resolve_many() interface below is the only thing callers
depend on, so the swap is contained to this file.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger("geolocation")

BATCH_ENDPOINT = "http://ip-api.com/batch"
BATCH_SIZE = 100
BATCH_FIELDS = "status,message,country,countryCode,city,lat,lon,isp,org,as,query"


def _load_cache(cache_path: Path) -> dict[str, Any]:
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("Geo cache at %s is corrupt, starting fresh", cache_path)
    return {}


def _save_cache(cache_path: Path, cache: dict[str, Any]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def resolve_many(ips: list[str], cache_path: Path, timeout: int = 10) -> dict[str, dict[str, Any]]:
    """Resolve a list of IPs to geolocation info, using/populating a local cache.

    Returns {ip: {country, countryCode, city, lat, lon, isp, org, as}} for every
    input IP. Private/reserved IPs and lookup failures map to
    {"country": "Unknown", ...}.
    """
    cache = _load_cache(cache_path)
    to_lookup = [ip for ip in dict.fromkeys(ips) if ip not in cache]
    logger.info("Geolocation: %d unique IPs total, %d not yet cached", len(set(ips)), len(to_lookup))

    for i in range(0, len(to_lookup), BATCH_SIZE):
        batch = to_lookup[i : i + BATCH_SIZE]
        try:
            resp = requests.post(
                f"{BATCH_ENDPOINT}?fields={BATCH_FIELDS}",
                json=[{"query": ip} for ip in batch],
                timeout=timeout,
            )
            resp.raise_for_status()
            results = resp.json()
            for ip, result in zip(batch, results):
                if result.get("status") == "success":
                    cache[ip] = result
                else:
                    logger.debug("Geo lookup failed for %s: %s", ip, result.get("message"))
                    cache[ip] = {"country": "Unknown", "countryCode": "", "city": "", "query": ip}
        except (requests.RequestException, ValueError) as exc:
            logger.warning("Geo batch lookup failed for %d IPs: %s", len(batch), exc)
            for ip in batch:
                cache.setdefault(ip, {"country": "Unknown", "countryCode": "", "city": "", "query": ip})

        # Stay comfortably under ip-api.com's free-tier batch rate limit.
        if i + BATCH_SIZE < len(to_lookup):
            time.sleep(4)

    _save_cache(cache_path, cache)
    return {ip: cache.get(ip, {"country": "Unknown", "countryCode": "", "city": "", "query": ip}) for ip in ips}
