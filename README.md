# T-Pot Honeypot Analysis

A T-Pot honeypot deployed on AWS EC2, paired with a Python pipeline that pulls its logs, parses them, geolocates and attributes the source addresses, and publishes a report every day through GitHub Actions.

The honeypot itself is upstream [T-Pot](https://github.com/telekom-security/tpotce) from Telekom Security. Everything in this repository (deployment, extraction, parsing, analysis, and the scheduled workflow) is mine. T-Pot produces logs; this code turns them into something readable.

## Architecture

**Sensor.** T-Pot (Mini flavor) on a `t3.medium` EC2 instance, Ubuntu, 32 GB disk, `us-east-1`. Ports 22, 80, and 443 are exposed as lures. The services listening there are imitations that log everything and grant nothing real. Management SSH runs on 64295.

**Pipeline.** `scripts/` connects over SSH, archives the T-Pot log directories, downloads and extracts them, parses the JSON-lines output, resolves each source IP to a country/city/ASN, applies brute-force and port-scan thresholds, and writes a Markdown report plus a metrics JSON.

| Script | Role |
|---|---|
| `deploy_tpot.py` | Provisions T-Pot on a fresh host |
| `extract_logs.py` | Archives and downloads remote logs |
| `analyze_logs.py` | Parses, aggregates, writes the report |
| `common/log_parsing.py` | Event loading, format normalisation, dedup |
| `common/config.py` | Config resolution, env-var merge |
| `generate_dashboard.py` | Chart-based HTML view of the same data |

**Automation.** `.github/workflows/honeypot-report.yml` runs the chain daily at 06:00 UTC and commits the output to `reports/`. No manual step.

## Findings

Figures are from the 2026-08-16 report, covering roughly eight days of continuous collection (2026-08-09 onward, plus an earlier partial capture on 2026-07-18).

**132,409 events, 2,080 unique attacker IPs**

By source: Suricata 99,710, p0f 22,374, honeypots 10,325. A further 65,790 events were excluded as allowlisted or private. Suricata and p0f observe all traffic crossing the host, including its own outbound connections and administrative access, so filtering those out is necessary to keep attacker metrics honest.

### Traffic shape

Port 22 draws the most attention by a wide margin (8,592 events), then 80 (4,091) and 443 (3,178). Port 64295, the non-standard management port, recorded 14 events. That is a small number but a useful one: moving SSH to a high port does not make it invisible, because scanners sweep there too.

Volume concentrates in the United States (3,624), China (3,364), Vietnam (1,251), the Netherlands (1,086), and Indonesia (938).

Several of the highest-volume sources are rented cloud infrastructure rather than compromised endpoints, including AWS EC2 in `us-east-1` and `ca-central-1`, Tencent Cloud, and Microsoft Azure. Attack traffic originating from the same providers that host the target is routine.

### Brute-force activity

Twenty sources crossed the >= 5 authentication-attempt threshold. The most persistent:

| IP | Auth attempts | Origin |
|---|---:|---|
| `220.168.118.133` | 368 | Changsha, CN |
| `160.187.174.22` | 247 | Deli Serdang, ID |
| `106.75.216.134` | 223 | Yangpu, CN (UCloud) |
| `103.48.192.62` | 177 | Hanoi, VN |
| `43.128.101.247` | 113 | Singapore (Tencent) |

Two sources crossed the port-scan threshold, touching 13 and 10 distinct ports respectively.

### Credential patterns

Around 1,780 credential attempts were recorded across the collection window. The distribution is extremely flat: the twenty most common passwords account for roughly 377 of them, meaning about 80% of attempts use passwords tried fewer than a dozen times each. This is dictionary spraying, not repetition of a short list.

The most frequent single passwords were `123456` (86), `password` (32), `admin` (23), and `root` (20). Alongside those, a distinct category appears:

`ubuntu` (17), `debian` (16), `apache` (15), `mysql` (14), `centos` (14), `www` (13), `linux` (13), `vps` (12), `host` (12)

These are distribution names, service names, and hosting terms used as passwords. The bots are wagering that the operator reused the OS or a running service as a credential. That is a different heuristic from numeric-string spraying, and it suggests wordlists assembled from observed real-world defaults rather than generic breach dumps.

Note that the report's credential table counts username/password *pairs*, while the figures above count passwords irrespective of username. A password like `123456` appears 86 times but is split across many usernames, so no single pair approaches that count. The two views answer different questions and are not directly comparable.

### Research scanners in the data

Not everything reaching the honeypot is hostile. Censys and the Shadowserver Foundation both appear in the attacker tables. Both are organisations that scan the internet to catalogue exposed hosts and notify network owners, and Censys in particular surfaces across several distinct addresses. Any honest reading of honeypot data has to separate this from genuine attack traffic, since counting it as hostile inflates the numbers.

No malware families were matched via Suricata signatures during this period.

## Limitations

The sensor runs T-Pot's **Mini** flavor, chosen to fit within 4 GB of RAM. Port 22 is served by the generic `honeypots` container rather than Cowrie, which means the sensor records authentication attempts and their outcome but does not emulate a shell session afterward.

Concretely: when a fake login is granted, no post-compromise behaviour is captured. There are no session transcripts and no malware samples, and `cowrie/downloads/` is empty by design rather than by accident. Running the Standard flavor on a larger instance would capture command histories and any payloads pulled down, which is the more valuable half of honeypot data.

Geolocation and ASN attribution come from a free keyless API and are indicative rather than authoritative. See `docs/METHODOLOGY.md` for caveats on the Suricata signature matching.

## Debugging notes

The first automated reports claimed **16 events and 0 unique attacker IPs**. Direct inspection of the box contradicted that: the raw logs held 32 SSH attempts and 294 HTTP requests for the same window.

Tracing it layer by layer:

* **Extraction was fine.** `extract_logs.py` archives whole service directories over SSH, so the rotated files were being downloaded correctly.
* **Parsing was not.** `load_events` and `dump_sample` globbed for `*.log` and `*.json` only. T-Pot rotates and compresses logs to names like `ssh.log.1.gz`, which match neither pattern. Those files were never opened. Not skipped, not logged as errors, simply never matched by the glob. The pipeline reported zero with complete confidence.

The fix was three parts: add `*.log.*` and `*.json.*` to the glob patterns; branch on the `.gz` suffix to open compressed files with `gzip.open(..., "rt")`; and deduplicate on `(src_ip, timestamp)` so that re-reading historical rotations on each run does not inflate counts. Dedup applies only to events carrying a `src_ip`, since flow records without one would otherwise collide falsely on `(None, timestamp)`.

Verification was against numbers derived by hand from the raw logs before the fix: 11 unique SSH source IPs, two HTTP sources tied at the top. The corrected pipeline reproduced them exactly. Event volume went from 16 to 6,747 on the same input.

A second, smaller issue came from the same family. `config.yaml` is gitignored, so ignore-list edits that worked locally never reached the Actions runner, and the operator's own address kept appearing as a top attacker in automated reports. Resolved by merging a `TPOT_IGNORE_IPS` repository variable with the file-based list rather than letting either silently override the other.

## Setup

**Requirements:** Python 3.11+, an EC2 host running T-Pot, SSH key access on port 64295.

```bash
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
# edit config.yaml: host, ssh_key_path, tpot user
python scripts/extract_logs.py     # pull a log snapshot
python scripts/analyze_logs.py     # parse and write the report
```

`config/config.yaml` is gitignored. It holds host and key paths and never reaches CI.

**For the scheduled workflow**, set in repository settings:

| Type | Name | Purpose |
|---|---|---|
| Secret | `EC2_SSH_PRIVATE_KEY` | Management SSH key |
| Variable | `TPOT_EC2_HOST` | Public address of the sensor |
| Variable | `TPOT_USER` | SSH user |
| Variable | `TPOT_IGNORE_IPS` | Comma-separated addresses to exclude from attacker metrics |

`TPOT_IGNORE_IPS` merges with `analysis.ignore_ips` from `config.yaml`, so local and CI runs can each hold entries the other does not.

**Note on hosts without an Elastic IP:** stopping and starting the instance assigns a new public address, invalidating both `config.yaml` and `TPOT_EC2_HOST`. Attach an Elastic IP if the sensor will be cycled on and off.

## Reports

`reports/LATEST.md` always holds the most recent run. Dated reports accumulate alongside it, with machine-readable metrics under `reports/data/`.
