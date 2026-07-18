#!/usr/bin/env python3
"""Pull raw honeypot/NSM logs off the T-Pot box over SSH and save them locally.

T-Pot's active containers write their logs to bind-mounted host directories
under ~/tpotce/data/<service>/log/. Rather than SFTP-walking many small
files one at a time, this script tars the relevant directories on the
remote host, downloads a single archive, and extracts it locally under
data/raw/<UTC timestamp>/ - fast and gives each run an immutable snapshot.

Usage:
    python scripts/extract_logs.py                 # pull default services
    python scripts/extract_logs.py --services honeypots suricata
    python scripts/extract_logs.py --keep-remote-tar   # don't delete the tar on the box
"""

from __future__ import annotations

import argparse
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.config import load_config, REPO_ROOT  # noqa: E402
from common.logging_utils import get_logger  # noqa: E402
from common.ssh_client import SSHClient  # noqa: E402

logger = get_logger("extract_logs")

TPOT_HOME_DIRNAME = "tpotce"
TPOT_REAL_SSH_PORT = 64295
DEFAULT_SERVICES = ["honeypots", "suricata", "p0f", "fatt"]


def utc_timestamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def extract_remote_logs(ssh: SSHClient, services: list[str], keep_remote_tar: bool = False) -> Path:
    remote_data_dir = f"/home/{ssh.user}/{TPOT_HOME_DIRNAME}/data"
    existing = []
    for svc in services:
        check = ssh.run(f"test -d {remote_data_dir}/{svc}", check=False)
        if check.ok:
            existing.append(svc)
        else:
            logger.warning("Remote log dir for service '%s' not found under %s - skipping.", svc, remote_data_dir)

    if not existing:
        raise RuntimeError(f"None of the requested services have log directories under {remote_data_dir}")

    run_id = utc_timestamp()
    remote_tar = f"/tmp/tpot_logs_{run_id}.tar.gz"
    dirs_arg = " ".join(existing)
    logger.info("Archiving remote log dirs on the box: %s", existing)
    ssh.run(f"sudo -n tar czf {remote_tar} -C {remote_data_dir} {dirs_arg}", timeout=300)

    size_result = ssh.run(f"du -h {remote_tar} | cut -f1", check=False)
    logger.info("Remote archive size: %s", size_result.stdout.strip())

    local_dir = REPO_ROOT / "data" / "raw" / run_id
    local_dir.mkdir(parents=True, exist_ok=True)
    local_tar = local_dir / "logs.tar.gz"

    ssh.run(f"sudo -n chmod 644 {remote_tar}")
    ssh.download_file(remote_tar, str(local_tar))

    if not keep_remote_tar:
        ssh.run(f"sudo -n rm -f {remote_tar}", check=False)

    logger.info("Extracting archive locally to %s", local_dir)
    with tarfile.open(local_tar, "r:gz") as tf:
        tf.extractall(local_dir, filter="data")  # noqa: S202 - trusted source (our own honeypot box)
    local_tar.unlink()

    return local_dir


def write_latest_pointer(extracted_dir: Path) -> None:
    pointer = REPO_ROOT / "data" / "raw" / "LATEST.txt"
    pointer.write_text(extracted_dir.name, encoding="utf-8")
    logger.info("Updated LATEST pointer -> %s", extracted_dir.name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=None)
    parser.add_argument("--services", nargs="+", default=DEFAULT_SERVICES, help="Which service log dirs to pull")
    parser.add_argument("--keep-remote-tar", action="store_true")
    parser.add_argument("--port", type=int, default=None, help="Override SSH port (default: T-Pot's real SSH port 64295)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if not cfg.ec2_host:
        logger.error("No EC2 host configured. Copy config/config.example.yaml to config/config.yaml and fill it in.")
        return 2

    port = args.port or TPOT_REAL_SSH_PORT
    try:
        with SSHClient(host=cfg.ec2_host, user=cfg.tpot_user, key_path=cfg.ssh_key_expanded, port=port) as ssh:
            extracted_dir = extract_remote_logs(ssh, args.services, args.keep_remote_tar)
        write_latest_pointer(extracted_dir)
        logger.info("Log extraction complete: %s", extracted_dir)
        return 0
    except Exception:
        logger.exception("Log extraction failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
