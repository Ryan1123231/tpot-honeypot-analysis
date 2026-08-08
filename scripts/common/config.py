"""Loads connection/deployment settings.

Precedence: environment variables (used in CI) override config/config.yaml
(used for local/manual runs). This lets the exact same scripts run both from
a developer's machine and from the GitHub Actions workflow without branching
logic scattered everywhere.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "config.yaml"


@dataclass
class TPotConfig:
    ec2_host: str
    ec2_port: int
    ec2_user: str
    ssh_key_path: str
    tpot_user: str
    tpot_flavor: str
    web_user: str
    web_password: str
    geo_provider: str
    geo_cache_path: str
    local_data_dir: str
    reports_dir: str
    ignore_ips: list[str]

    @property
    def ssh_key_expanded(self) -> str:
        return str(Path(self.ssh_key_path).expanduser())


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_config(config_path: str | Path | None = None) -> TPotConfig:
    """Load config, preferring environment variables over the YAML file.

    Recognized environment variables (all optional, override the YAML file):
      TPOT_EC2_HOST, TPOT_EC2_PORT, TPOT_EC2_USER, TPOT_SSH_KEY_PATH,
      TPOT_SSH_KEY_CONTENT (written to a temp file if set, used by CI),
      TPOT_USER, TPOT_FLAVOR, TPOT_WEB_USER, TPOT_WEB_PASSWORD

    TPOT_IGNORE_IPS is the one exception: it's a comma-separated list that is
    MERGED with (not overridden by) analysis.ignore_ips from the YAML file.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    raw = _load_yaml(path)

    ec2 = raw.get("ec2", {})
    tpot = raw.get("tpot", {})
    geo = raw.get("geolocation", {})
    paths = raw.get("paths", {})
    analysis = raw.get("analysis", {})

    # Merge (not override) so a locally-checked-out config.yaml and the CI-only
    # TPOT_IGNORE_IPS repo variable both take effect - config.yaml is gitignored,
    # so CI has no other way to know about e.g. the deploying admin's own IP.
    ignore_ips_env = os.environ.get("TPOT_IGNORE_IPS", "")
    ignore_ips = list(analysis.get("ignore_ips", [])) + ignore_ips_env.split(",")

    ssh_key_path = os.environ.get("TPOT_SSH_KEY_PATH", ec2.get("ssh_key_path", "~/.ssh/id_rsa_cloudways"))

    key_content = os.environ.get("TPOT_SSH_KEY_CONTENT")
    if key_content:
        # CI path: the private key comes from a GitHub Actions secret as a
        # string. Materialize it to a restricted-permission temp file so
        # paramiko can load it like any other key file.
        key_file = REPO_ROOT / ".ssh_key_ci"
        key_file.write_text(key_content, encoding="utf-8")
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass  # best-effort on platforms without POSIX perms (e.g. Windows)
        ssh_key_path = str(key_file)

    return TPotConfig(
        ec2_host=os.environ.get("TPOT_EC2_HOST", ec2.get("host", "")),
        ec2_port=int(os.environ.get("TPOT_EC2_PORT", ec2.get("port", 22))),
        ec2_user=os.environ.get("TPOT_EC2_USER", ec2.get("bootstrap_user", "root")),
        ssh_key_path=ssh_key_path,
        tpot_user=os.environ.get("TPOT_USER", tpot.get("user", "tpot")),
        tpot_flavor=os.environ.get("TPOT_FLAVOR", tpot.get("flavor", "i")),
        web_user=os.environ.get("TPOT_WEB_USER", tpot.get("web_user", "admin")),
        web_password=os.environ.get("TPOT_WEB_PASSWORD", tpot.get("web_password", "")),
        geo_provider=os.environ.get("TPOT_GEO_PROVIDER", geo.get("provider", "ip-api")),
        geo_cache_path=os.environ.get("TPOT_GEO_CACHE_PATH", geo.get("cache_path", "data/geo_cache.json")),
        local_data_dir=os.environ.get("TPOT_LOCAL_DATA_DIR", paths.get("local_data_dir", "data")),
        reports_dir=os.environ.get("TPOT_REPORTS_DIR", paths.get("reports_dir", "reports")),
        ignore_ips=list(dict.fromkeys(ip.strip() for ip in ignore_ips if ip.strip())),
    )
