# Methodology

## Why T-Pot, why Mini flavor

[T-Pot](https://github.com/telekom-security/tpotce) bundles ~20 honeypot
daemons plus network-monitoring tooling (Suricata, p0f, fatt) behind a
single Docker Compose stack. Deutsche Telekom's own sizing guidance is:

| Flavor | RAM | Disk |
|---|---|---|
| Standard/Hive | 16GB | 256GB |
| Sensor | 8GB | 128GB |
| **Mini** | ~4GB | ~32GB |

A `t3.micro` (1GB RAM) doesn't meet even the Mini flavor's floor - the
Elasticsearch container alone typically wants a 1-2GB heap. This project
targets a `t3.medium` (4GB RAM / 32GB disk) running the **Mini** flavor,
which is the smallest official flavor and the only one that fits.

## What's running, and what isn't

Mini's default container list includes eight "honeypot" services, but only
one of them - `honeypots` (the QeeqBox multi-protocol honeypot) - covers
SSH/HTTP/HTTPS; it does so by exposing 31 ports at once (FTP, Telnet, SMTP,
databases, etc). Since the brief was specifically "keep SSH, HTTP, HTTPS
active, disable the rest," `deploy_tpot.py` does two things after install:

1. **Trims `honeypots`' port list** down to just `22:22`, `80:80`, `443:443`
   - the container keeps running, it's just no longer reachable on the
     other 28 ports.
2. **Removes entirely**: the other protocol-specific honeypots
   (adbhoney/ciscoasa/conpot variants/dicompot/medpot), the generic
   catch-all `honeytrap`, and the heavy ELK/Kibana/map/`ewsposter`/
   `spiderfoot` stack.

The ELK stack removal is deliberate, not just a resource-saving move: this
repo's own Python scripts (`analyze_logs.py`, `generate_dashboard.py`) read
the honeypots' raw JSON log files directly and do the aggregation/
visualization that Elasticsearch+Kibana would otherwise provide. Running
both would be redundant and Elasticsearch alone can eat the RAM budget of
the entire box.

**Kept**: `tpotinit` (required by everything else), `honeypots` (trimmed to
22/80/443), `suricata`, `p0f`, `fatt`. The last three don't accept
connections themselves - they passively watch the box's network interface
and are the source of the "malware family" and some "attack pattern" data
below (Suricata in particular ships with the ET-Open IDS ruleset, which is
what actually recognizes things like Mirai or Log4Shell traffic).

Edit `DISABLE_SERVICES` / `ALWAYS_KEEP` at the top of `scripts/deploy_tpot.py`
if you want a different mix (e.g. re-enable Kibana for its own dashboard
alongside this repo's).

## How each report metric is derived

- **Top attacking IPs**: raw event count per source IP across all kept
  honeypots' logs plus Suricata alerts.
- **Countries/geolocation**: unique attacker IPs are batch-resolved via
  [ip-api.com](https://ip-api.com)'s free, keyless endpoint and cached
  locally (`data/geo_cache.json`) so repeat IPs aren't re-queried. Swap
  `scripts/common/geolocation.py` for MaxMind GeoLite2 if you need
  higher accuracy or hit the free tier's rate limit.
- **Attack types/patterns**:
  - *Brute force*: any IP with >= 5 authentication attempts (username/
    password fields present, or a login-type event) against a honeypot.
  - *Port scanning*: any IP that touched >= 5 distinct destination ports.
  - *Web attacks*: regex matching against request paths and Suricata alert
    signatures for common patterns (SQLi, path traversal, Log4Shell probes,
    WordPress probing, webshell access, generic RCE attempts). This is
    intentionally simple pattern-matching, not a WAF-grade classifier - treat
    matches as leads, not verdicts.
  - Thresholds live at the top of `scripts/analyze_logs.py`
    (`BRUTE_FORCE_THRESHOLD`, `PORT_SCAN_THRESHOLD`).
- **Ports targeted**: destination port frequency from the honeypot logs.
- **Malware families**: Suricata alert *signature* text matched against a
  curated regex list (Mirai, Gafgyt/Bashlite, Emotet, TrickBot, Cobalt
  Strike, Log4Shell, XMRig, etc. - see `MALWARE_FAMILY_PATTERNS` in
  `analyze_logs.py`). **Caveat**: T-Pot's Mini flavor doesn't run Dionaea
  (the honeypot that actually captures dropped malware binaries), so this
  is IDS-signature-based detection of malware *activity*, not sample
  capture/sandboxing. If you want real binary capture + family ID, that
  needs the Sensor or Standard flavor and a much bigger box.
- **Timeline**: events bucketed by hour and by day from each log line's
  timestamp.

## Calibrating the parser against real traffic

`scripts/common/log_parsing.py` normalizes each honeypot's JSON log lines
into a common schema using ordered lists of "acceptable field names"
(e.g. an IP might show up as `src_ip`, `source_ip`, or `srcip` depending on
the container). These lists were initially set from T-Pot's documented log
layout, then corrected against a real first deployment - `p0f` turned out to
use `client_ip`/`server_ip`/`client_port`/`server_port` rather than the more
common `src_*`/`dest_*` naming, which is now reflected in
`SRC_IP_KEYS`/`DEST_PORT_KEYS`/`SRC_PORT_KEYS`.

If you deploy against a different T-Pot version and metrics look thin, run:

```bash
python scripts/analyze_logs.py --dump-sample
```

This prints a handful of raw log lines per source. Compare the actual field
names against the `*_KEYS` lists in `scripts/common/log_parsing.py` and add
any that are missing. If parsing is working, `analyze_logs.py`'s normal run
will report non-trivial event counts per source instead of "0 events
parsed."

## Filtering out non-attacker noise

Two things will otherwise pollute attacker-facing metrics, discovered by
running against a real (freshly deployed, otherwise-idle) box:

1. **p0f and Suricata's non-alert event types (`flow`, `dns`, `tls`, ...)
   record *all* traffic through the box, not just inbound attacks** -
   including the box's own outbound connections (apt updates, NTP, DNS).
   `compute_metrics()` in `analyze_logs.py` only lets an event contribute to
   attacker/IP/port/timeline stats if it came from the `honeypots` container
   (which by construction only receives inbound connections) or is a
   Suricata *alert* specifically. Other event types still count toward
   `events_by_source` for visibility, just not toward "attacker" numbers.
2. **Suricata doesn't distinguish your own admin traffic from an
   attacker** - connecting to manage the box (e.g. SSH to port 64295) can
   itself trigger a low-severity alert. Set `analysis.ignore_ips` in
   `config.yaml` to your own public IP(s) to exclude them. Separately,
   private/link-local/reserved source IPs (e.g. AWS's `169.254.169.x`
   metadata service) are filtered out automatically, since a real internet
   attacker's source IP can never be one of those.

## Ethics / scope

This is a *defensive* research honeypot on infrastructure you own, used to
observe unsolicited internet scanning/attack traffic - not to attract,
retaliate against, or interact offensively with anyone. Don't point this
setup at infrastructure you don't own or have explicit authorization to
run a honeypot on.
