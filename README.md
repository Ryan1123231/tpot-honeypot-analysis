# T-Pot Honeypot + Python Attack Analysis

Automated deployment and analysis pipeline for a [T-Pot](https://github.com/telekom-security/tpotce)
multi-honeypot sensor on a single EC2 instance, with a custom Python
pipeline (no Kibana/ELK needed) that turns raw honeypot logs into daily
Markdown reports and an HTML dashboard, committed automatically via GitHub
Actions.

```
Internet
   |
   v
EC2 (t3.medium, Ubuntu 24) ── T-Pot Mini (Docker) ──> honeypot logs on disk
   ^                                                        |
   | SSH (key auth)                                         |
   |                                                        v
GitHub Actions (daily) ── extract_logs.py ── analyze_logs.py ── generate_dashboard.py
                                                    |
                                                    v
                                        reports/*.md, reports/dashboard.html
                                        (committed back to this repo)
```

## What's actually running on the honeypot

Only three things are internet-facing: an SSH honeypot, an HTTP honeypot,
and an HTTPS honeypot (all served by T-Pot's `honeypots` container, trimmed
down from its default 31 ports). Passive network monitoring (Suricata/p0f/
fatt) runs alongside for attack-pattern and malware-family detection.
Everything else T-Pot normally ships with Mini (other protocol honeypots,
Kibana/Elasticsearch/Logstash) is disabled - see
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for exactly what and why.

## Repo layout

```
scripts/
  deploy_tpot.py         Installs & configures T-Pot on the EC2 box (run once)
  extract_logs.py         Pulls raw logs from the box over SSH (run on a schedule)
  analyze_logs.py          Parses logs -> reports/*.md + reports/data/metrics_*.json
  generate_dashboard.py    Builds reports/dashboard.html (Plotly charts) from the metrics
  common/                  Shared SSH client, config loader, log parsing, geolocation
config/
  config.example.yaml      Copy to config.yaml for local runs (gitignored)
.github/workflows/
  honeypot-report.yml      Daily: extract -> analyze -> dashboard -> commit reports/
reports/                   Generated output (see reports/README.md)
docs/
  METHODOLOGY.md            How each metric is computed, and its limitations
data/                       Local scratch space for pulled logs (gitignored)
```

## Prerequisites

- An EC2 instance sized for T-Pot Mini: **4GB+ RAM, 32GB+ disk** (a
  `t3.micro` is *not* big enough - see `docs/METHODOLOGY.md`). This repo
  assumes Ubuntu 24.04.
- The instance's security group must allow inbound TCP 22, 80, 443 (so the
  honeypot actually gets attacked) and TCP 64295 (where the *real* sshd
  moves to after install - **make sure this is open before deploying, or
  you can be locked out of the box**).
- Python 3.11+ and `pip install -r requirements.txt` locally, for
  manual/local runs.
- SSH key auth already working to the box as `root` (used only for initial
  bootstrap - `deploy_tpot.py` creates a dedicated non-root sudo user for
  everything after that, since T-Pot's installer refuses to run as root).

## Quickstart

```bash
cp config/config.example.yaml config/config.yaml
# edit config.yaml: set ec2.host, ec2.ssh_key_path

pip install -r requirements.txt

# 1. Deploy T-Pot (idempotent - safe to re-run; takes ~15-20 minutes)
python scripts/deploy_tpot.py

# 2. Pull logs
python scripts/extract_logs.py

# 3. Analyze -> Markdown report + JSON metrics
python scripts/analyze_logs.py

# 4. Build the HTML dashboard
python scripts/generate_dashboard.py
```

Open `reports/LATEST.md` or `reports/dashboard.html`.

## Automating it (GitHub Actions)

The workflow in `.github/workflows/honeypot-report.yml` runs daily
(`0 6 * * *` UTC - edit the cron line for weekly instead) and on manual
dispatch. It needs:

**Repo secrets** (Settings → Secrets and variables → Actions → Secrets):
- `EC2_SSH_PRIVATE_KEY` - the contents of your private key file (e.g.
  `id_rsa_cloudways`). Generate a **dedicated key** for this if you can,
  rather than reusing a key with broader access elsewhere.

**Repo variables** (same page → Variables):
- `TPOT_EC2_HOST` - the box's IP or hostname
- `TPOT_USER` - the sudo user `deploy_tpot.py` created (default: `tpot`)

The workflow pulls logs, analyzes them, regenerates the dashboard, and
commits any changes under `reports/` back to the repo automatically. Raw
logs (`data/`) are never committed - only the derived Markdown/JSON/HTML.

## How to interpret the reports

Each report starts with totals (events analyzed, unique attacker IPs) and
breaks down into: top attacking IPs with geolocation, top countries, top
targeted ports, likely brute-force/port-scan sources, matched web-attack
signatures, malware families (from Suricata IDS alerts), top credential
pairs attempted, and a daily timeline. None of these numbers imply your box
was "hacked" - a honeypot is *designed* to attract and log this traffic;
high numbers mean the honeypot is doing its job, not that anything of
yours was compromised. Full detail on how each number is computed,
including known limitations (e.g. malware-family detection is
signature-based, not binary capture/sandboxing on the Mini flavor), is in
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## Security notes

- `config/config.yaml`, any `*.pem`/`*_rsa` key files, and
  `config/tpot_web_credentials.txt` are gitignored - never commit them.
- The dedicated sudo user `deploy_tpot.py` creates has passwordless sudo;
  this doesn't meaningfully increase risk since whoever holds the SSH key
  already has root via the bootstrap account, but don't reuse that key
  elsewhere.
- This is a defensive/research honeypot on infrastructure you own - see the
  "Ethics / scope" note at the bottom of `docs/METHODOLOGY.md`.

## License

MIT - see [`LICENSE`](LICENSE).
