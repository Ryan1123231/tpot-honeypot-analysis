#!/usr/bin/env python3
"""Fully automated T-Pot deployment onto a fresh Ubuntu 24.04 EC2 host.

What this does, in order:
  1. Connects as the bootstrap user (root) on port 22.
  2. Sanity-checks OS/RAM/disk against the chosen T-Pot flavor's minimums.
  3. Creates a dedicated non-root sudo user (T-Pot's installer refuses to run
     as root) and copies the same SSH key so nothing else changes about how
     you log in.
  4. Clones telekom-security/tpotce and runs its unattended installer.
  5. Reboots the box (required by T-Pot to finalize network/iptables setup)
     and reconnects on T-Pot's new SSH port (64295).
  6. Waits for the Docker Compose stack to come up healthy.
  7. Trims the compose file down to just the honeypots you asked to keep
     (SSH/HTTP/HTTPS-facing) plus lightweight network monitoring (Suricata/
     p0f/fatt), removing everything else (other protocol honeypots, and the
     heavy ELK/Kibana/map stack - this repo's own Python scripts do the log
     analysis instead, so we don't pay Elasticsearch's RAM cost).
  8. Verifies the result: expected containers running, expected ports open.

Usage:
    python scripts/deploy_tpot.py                  # full run
    python scripts/deploy_tpot.py --dry-run         # print the plan, do nothing
    python scripts/deploy_tpot.py --skip-install    # re-run trimming/verify only

See docs/METHODOLOGY.md for *why* Mini flavor + this particular keep-list.
"""

from __future__ import annotations

import argparse
import io
import json
import secrets
import string
import sys
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.config import load_config, REPO_ROOT  # noqa: E402
from common.logging_utils import get_logger  # noqa: E402
from common.ssh_client import SSHClient, CommandError  # noqa: E402

logger = get_logger("deploy_tpot")

TPOT_REPO_URL = "https://github.com/telekom-security/tpotce.git"
TPOT_REAL_SSH_PORT = 64295  # where T-Pot's installer moves the real sshd to
TPOT_HOME_DIRNAME = "tpotce"

# Minimums per T-Pot flavor (RAM in MB, disk in GB free on the root volume).
# Source: telekom-security/tpotce README (Standard/Sensor) + community
# guidance for Mini. Verify against current upstream docs before changing
# flavor - these thresholds change between T-Pot releases.
FLAVOR_MINIMUMS = {
    "i": {"name": "Mini", "ram_mb": 4000, "disk_gb": 30},
    "s": {"name": "Sensor", "ram_mb": 8000, "disk_gb": 128},
    "h": {"name": "Hive/Standard", "ram_mb": 16000, "disk_gb": 256},
}

# Honeypot containers to keep running and internet-facing.
# "honeypots" is the QeeqBox multi-protocol container; by default it exposes
# 31 ports (ftp, telnet, smtp, databases, etc). We keep the container but
# trim its port mappings down to just SSH/HTTP/HTTPS per the user's request.
HONEYPOTS_SERVICE = "honeypots"
HONEYPOTS_KEEP_PORTS = ["22:22", "80:80", "443:443"]

# Everything else in this list gets removed entirely from docker-compose.yml.
# Adjust freely - see docs/METHODOLOGY.md for what each one does.
DISABLE_SERVICES = [
    # other protocol-specific honeypots (outside ssh/http/https scope)
    "adbhoney", "ciscoasa", "conpot_IEC104", "conpot_guardian_ast",
    "conpot_ipmi", "conpot_kamstrup_382", "dicompot", "medpot",
    "honeytrap",  # generic catch-all honeypot, overlaps with 'honeypots'
    # heavy ELK/visualization stack - our own Python scripts replace this
    "elasticsearch", "logstash", "kibana", "map_redis", "map_web", "map_data",
    "nginx", "spiderfoot",
    "ewsposter",  # forwards data to Deutsche Telekom's public sensor network
]

# Always kept regardless of DISABLE_SERVICES: tpotinit (required by
# everything else via depends_on: service_healthy) and the lightweight
# network-monitoring trio (suricata/p0f/fatt) which feed attack-pattern /
# malware-family detection in analyze_logs.py.
ALWAYS_KEEP = {"tpotinit", "suricata", "p0f", "fatt", HONEYPOTS_SERVICE}


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def check_prerequisites(ssh: SSHClient, flavor: str) -> None:
    logger.info("=== Phase 1: pre-flight checks ===")

    os_release = ssh.run("cat /etc/os-release", check=False).stdout
    if "ubuntu" not in os_release.lower():
        logger.warning("This host does not look like Ubuntu; T-Pot's installer targets Ubuntu/Debian. Proceeding anyway.")
    logger.info("OS release info:\n%s", os_release.strip())

    mem_kb = int(ssh.run("grep MemTotal /proc/meminfo | awk '{print $2}'", check=False).stdout.strip() or 0)
    mem_mb = mem_kb / 1024
    disk_gb = float(ssh.run("df -BG --output=avail / | tail -1 | tr -d 'G '", check=False).stdout.strip() or 0)

    minimums = FLAVOR_MINIMUMS[flavor]
    logger.info(
        "Host resources: %.0fMB RAM (need >=%dMB for %s), %.0fGB free disk (need >=%dGB)",
        mem_mb, minimums["ram_mb"], minimums["name"], disk_gb, minimums["disk_gb"],
    )
    if mem_mb < minimums["ram_mb"]:
        raise RuntimeError(
            f"Insufficient RAM for T-Pot {minimums['name']}: have {mem_mb:.0f}MB, need >={minimums['ram_mb']}MB. "
            "Resize the instance before continuing."
        )
    if disk_gb < minimums["disk_gb"]:
        raise RuntimeError(
            f"Insufficient disk for T-Pot {minimums['name']}: have {disk_gb:.0f}GB free, need >={minimums['disk_gb']}GB. "
            "Grow the root EBS volume before continuing."
        )
    logger.info("Resource check passed.")


def ensure_tpot_user(ssh: SSHClient, tpot_user: str) -> None:
    logger.info("=== Phase 2: creating non-root sudo user '%s' (T-Pot refuses to install as root) ===", tpot_user)

    exists = ssh.run(f"id -u {tpot_user}", check=False).ok
    if exists:
        logger.info("User '%s' already exists, skipping creation.", tpot_user)
    else:
        ssh.run(f"useradd -m -s /bin/bash {tpot_user}")
        ssh.run(f"mkdir -p /home/{tpot_user}/.ssh")
        ssh.run(f"cp /root/.ssh/authorized_keys /home/{tpot_user}/.ssh/authorized_keys")
        ssh.run(f"chown -R {tpot_user}:{tpot_user} /home/{tpot_user}/.ssh")
        ssh.run(f"chmod 700 /home/{tpot_user}/.ssh && chmod 600 /home/{tpot_user}/.ssh/authorized_keys")
        # NOPASSWD sudo: acceptable here because whoever already holds the
        # SSH private key has unrestricted root access via the bootstrap
        # 'root' account anyway - this doesn't raise the box's actual attack
        # surface, it just gives the unattended installer a non-root account
        # to run under, as T-Pot requires.
        ssh.run(f'echo "{tpot_user} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/{tpot_user}')
        ssh.run(f"chmod 440 /etc/sudoers.d/{tpot_user}")
        logger.info("Created user '%s' with passwordless sudo and the same SSH key as root.", tpot_user)

    ssh.run("apt-get update -y && apt-get install -y git curl")


def run_tpot_installer(ssh_tpot: SSHClient, flavor: str, web_user: str, web_password: str) -> None:
    logger.info("=== Phase 3: installing T-Pot (flavor=%s) ===", flavor)

    if ssh_tpot.path_exists(f"~/{TPOT_HOME_DIRNAME}"):
        logger.info("~/%s already exists - assuming a previous install attempt; not re-cloning.", TPOT_HOME_DIRNAME)
    else:
        ssh_tpot.run(f"git clone {TPOT_REPO_URL} ~/{TPOT_HOME_DIRNAME}", timeout=180)

    install_cmd = (
        f"cd ~/{TPOT_HOME_DIRNAME} && "
        f"sudo -n ./install.sh -s -t {flavor} -u {web_user} -p '{web_password}'"
    )
    logger.info("Running unattended installer (this typically takes 10-20 minutes)...")
    result = ssh_tpot.run(install_cmd, check=False, timeout=2400, log_output=True)
    if not result.ok:
        raise CommandError(install_cmd, result.exit_code, result.stdout, result.stderr)
    logger.info("Installer finished successfully.")


def reboot_and_reconnect(ssh_tpot: SSHClient, host: str, tpot_user: str, key_path: str) -> SSHClient:
    logger.info("=== Phase 4: rebooting to finalize T-Pot setup ===")
    try:
        ssh_tpot.run("sudo -n reboot", check=False, timeout=5)
    except Exception:  # connection drops mid-command as the box goes down - expected
        pass
    ssh_tpot.close()

    time.sleep(15)  # give the box a moment to actually go down before polling
    new_client = SSHClient(host=host, user=tpot_user, key_path=key_path, port=TPOT_REAL_SSH_PORT)
    new_client.wait_for_reboot(new_port=TPOT_REAL_SSH_PORT, max_wait_s=480, poll_interval_s=10)
    logger.info("Reconnected on the new real-SSH port tcp/%d.", TPOT_REAL_SSH_PORT)
    return new_client


def wait_for_stack_healthy(ssh: SSHClient, max_wait_s: int = 300) -> None:
    logger.info("=== Phase 5: waiting for the Docker Compose stack to come up ===")
    deadline = time.time() + max_wait_s
    while time.time() < deadline:
        result = ssh.run(f"cd ~/{TPOT_HOME_DIRNAME} && sudo -n docker compose ps --format json", check=False)
        if result.ok and result.stdout.strip():
            logger.info("Compose stack is reporting status; proceeding to trim step.")
            return
        time.sleep(10)
    raise TimeoutError("Docker Compose stack did not report any running services within the timeout.")


def trim_compose_file(ssh: SSHClient) -> None:
    logger.info("=== Phase 6: trimming docker-compose.yml to the requested keep-list ===")
    remote_compose_path = f"/home/{ssh.user}/{TPOT_HOME_DIRNAME}/docker-compose.yml"
    local_tmp = REPO_ROOT / "data" / "_remote_docker-compose.yml"
    local_tmp.parent.mkdir(parents=True, exist_ok=True)

    ssh.download_file(remote_compose_path, str(local_tmp))
    with open(local_tmp, "r", encoding="utf-8") as fh:
        compose = yaml.safe_load(fh)

    services = compose.get("services", {})
    present = set(services.keys())
    to_remove = [s for s in DISABLE_SERVICES if s in present]
    unexpected = present - ALWAYS_KEEP - set(DISABLE_SERVICES)
    if unexpected:
        logger.warning(
            "Services present in docker-compose.yml that aren't in either KEEP or DISABLE lists "
            "(leaving them as-is, but you may want to classify them): %s",
            sorted(unexpected),
        )

    for svc in to_remove:
        del services[svc]
        logger.info("Removed service: %s", svc)

    if HONEYPOTS_SERVICE in services:
        original_ports = services[HONEYPOTS_SERVICE].get("ports", [])
        services[HONEYPOTS_SERVICE]["ports"] = HONEYPOTS_KEEP_PORTS
        logger.info(
            "Trimmed '%s' ports from %d entries to %s",
            HONEYPOTS_SERVICE, len(original_ports), HONEYPOTS_KEEP_PORTS,
        )
    else:
        logger.warning("Service '%s' not found in docker-compose.yml - nothing to trim.", HONEYPOTS_SERVICE)

    compose["services"] = services
    buf = io.StringIO()
    yaml.safe_dump(compose, buf, sort_keys=False)
    edited_local = REPO_ROOT / "data" / "_edited_docker-compose.yml"
    edited_local.write_text(buf.getvalue(), encoding="utf-8")

    # Upload the edited file and apply it.
    sftp = ssh._client.open_sftp()  # noqa: SLF001 - deliberate use of the underlying client
    try:
        sftp.put(str(edited_local), remote_compose_path)
    finally:
        sftp.close()
    logger.info("Uploaded trimmed docker-compose.yml.")

    ssh.run("sudo -n systemctl stop tpot", check=False, timeout=60)
    ssh.run(
        f"cd ~/{TPOT_HOME_DIRNAME} && sudo -n docker compose up -d --remove-orphans",
        timeout=300,
    )
    ssh.run("sudo -n systemctl start tpot", check=False, timeout=60)
    logger.info("Applied trimmed compose file and restarted the stack.")


def verify_deployment(ssh: SSHClient) -> dict:
    logger.info("=== Phase 7: verification ===")
    ps_result = ssh.run(f"cd ~/{TPOT_HOME_DIRNAME} && sudo -n docker compose ps --format json", check=False)
    running_services = []
    for line in ps_result.stdout.strip().splitlines():
        try:
            entry = json.loads(line)
            running_services.append({"name": entry.get("Service"), "state": entry.get("State")})
        except json.JSONDecodeError:
            continue

    ports_result = ssh.run("sudo -n ss -tulpn | grep -E ':(22|80|443|64295)\\b'", check=False)
    logger.info("Listening ports:\n%s", ports_result.stdout.strip())

    summary = {
        "running_services": running_services,
        "listening_ports_raw": ports_result.stdout.strip(),
        "ssh_management_port": TPOT_REAL_SSH_PORT,
    }
    expected_running = ALWAYS_KEEP
    actually_running = {s["name"] for s in running_services if s["state"] and "running" in s["state"].lower()}
    missing = expected_running - actually_running
    if missing:
        logger.warning("Expected services not reported as running: %s", sorted(missing))
    else:
        logger.info("All expected services (%s) are running.", sorted(expected_running))

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=None, help="Path to config.yaml (default: config/config.yaml)")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan without connecting to anything")
    parser.add_argument("--skip-install", action="store_true", help="Assume T-Pot is already installed; only trim + verify")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if not cfg.ec2_host:
        logger.error("No EC2 host configured. Copy config/config.example.yaml to config/config.yaml and fill it in.")
        return 2

    flavor = cfg.tpot_flavor
    web_password = cfg.web_password or generate_password()

    if args.dry_run:
        logger.info("[DRY RUN] Would deploy T-Pot flavor '%s' to %s@%s using key %s",
                     flavor, cfg.ec2_user, cfg.ec2_host, cfg.ssh_key_expanded)
        logger.info("[DRY RUN] Would create sudo user '%s', keep services %s, disable %s",
                     cfg.tpot_user, sorted(ALWAYS_KEEP), DISABLE_SERVICES)
        return 0

    try:
        if not args.skip_install:
            bootstrap = SSHClient(host=cfg.ec2_host, user=cfg.ec2_user, key_path=cfg.ssh_key_expanded, port=cfg.ec2_port)
            bootstrap.connect(retries=3, retry_wait=10)
            check_prerequisites(bootstrap, flavor)
            ensure_tpot_user(bootstrap, cfg.tpot_user)
            bootstrap.close()

            tpot_conn = SSHClient(host=cfg.ec2_host, user=cfg.tpot_user, key_path=cfg.ssh_key_expanded, port=cfg.ec2_port)
            tpot_conn.connect(retries=3, retry_wait=10)
            run_tpot_installer(tpot_conn, flavor, cfg.web_user, web_password)

            creds_file = REPO_ROOT / "config" / "tpot_web_credentials.txt"
            creds_file.write_text(f"web_user={cfg.web_user}\nweb_password={web_password}\n", encoding="utf-8")
            logger.info("Web UI credentials saved to %s (gitignored, kept local only)", creds_file)

            live = reboot_and_reconnect(tpot_conn, cfg.ec2_host, cfg.tpot_user, cfg.ssh_key_expanded)
        else:
            live = SSHClient(host=cfg.ec2_host, user=cfg.tpot_user, key_path=cfg.ssh_key_expanded, port=TPOT_REAL_SSH_PORT)
            live.connect(retries=3, retry_wait=10)

        wait_for_stack_healthy(live)
        trim_compose_file(live)
        time.sleep(15)  # let the trimmed stack settle before checking it
        summary = verify_deployment(live)
        live.close()

        summary_path = REPO_ROOT / "data" / "deployment_summary.json"
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.info("Deployment summary written to %s", summary_path)
        logger.info(
            "DONE. Reconnect for management with: ssh -p %d -i %s %s@%s",
            TPOT_REAL_SSH_PORT, cfg.ssh_key_expanded, cfg.tpot_user, cfg.ec2_host,
        )
        return 0
    except Exception:
        logger.exception("Deployment failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
