"""Thin wrapper around paramiko used by every script that talks to the EC2 box.

Centralizes: key-based auth, connect-with-retry (needed because the T-Pot
installer reboots the host and moves sshd to a new port), streaming command
execution with real-time logging, and SFTP file transfer.
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

logger = logging.getLogger("ssh_client")


class CommandError(RuntimeError):
    """Raised when a remote command exits non-zero and check=True was passed."""

    def __init__(self, command: str, exit_code: int, stdout: str, stderr: str):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"Remote command failed (exit {exit_code}): {command}\nstderr: {stderr[:2000]}")


@dataclass
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class SSHClient:
    """A single persistent SSH connection with helpers for exec + sftp."""

    def __init__(self, host: str, user: str, key_path: str, port: int = 22, timeout: int = 20):
        self.host = host
        self.user = user
        self.key_path = str(Path(key_path).expanduser())
        self.port = port
        self.timeout = timeout
        self._client: paramiko.SSHClient | None = None

    def connect(self, retries: int = 1, retry_wait: int = 10) -> None:
        last_err: Exception | None = None
        for attempt in range(1, retries + 1):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.user,
                    key_filename=self.key_path,
                    timeout=self.timeout,
                    banner_timeout=self.timeout,
                    auth_timeout=self.timeout,
                )
                self._client = client
                logger.info("Connected to %s@%s:%s (attempt %d/%d)", self.user, self.host, self.port, attempt, retries)
                return
            except (paramiko.SSHException, socket.error, EOFError) as exc:
                last_err = exc
                logger.warning(
                    "SSH connect attempt %d/%d to %s:%s failed: %s",
                    attempt, retries, self.host, self.port, exc,
                )
                if attempt < retries:
                    time.sleep(retry_wait)
        raise ConnectionError(f"Could not connect to {self.host}:{self.port} after {retries} attempts") from last_err

    def wait_for_reboot(self, new_port: int | None = None, max_wait_s: int = 300, poll_interval_s: int = 10) -> None:
        """Block until the host is reachable again on (optionally) a new port.

        Used after triggering a reboot (e.g. T-Pot install finishing), where
        the box goes down, comes back up, and possibly sshd has moved port.
        """
        target_port = new_port or self.port
        logger.info("Waiting up to %ds for %s:%s to come back after reboot...", max_wait_s, self.host, target_port)
        deadline = time.time() + max_wait_s
        self.close()
        while time.time() < deadline:
            try:
                with socket.create_connection((self.host, target_port), timeout=5):
                    logger.info("%s:%s is accepting connections again", self.host, target_port)
                    self.port = target_port
                    self.connect(retries=3, retry_wait=5)
                    return
            except OSError:
                time.sleep(poll_interval_s)
        raise TimeoutError(f"{self.host}:{target_port} did not come back within {max_wait_s}s")

    def run(self, command: str, check: bool = True, timeout: int | None = None, log_output: bool = True) -> CommandResult:
        """Run a command and return once it completes, streaming output to the logger."""
        if self._client is None:
            raise RuntimeError("Not connected - call connect() first")

        logger.debug("Running remote command: %s", command)
        stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        stdin.close()

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        channel = stdout.channel

        while True:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode("utf-8", errors="replace")
                stdout_lines.append(chunk)
                if log_output:
                    for line in chunk.splitlines():
                        if line.strip():
                            logger.info("  [remote] %s", line)
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                stderr_lines.append(chunk)
                if log_output:
                    for line in chunk.splitlines():
                        if line.strip():
                            logger.info("  [remote:stderr] %s", line)
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.2)

        exit_code = channel.recv_exit_status()
        result = CommandResult(
            command=command,
            exit_code=exit_code,
            stdout="".join(stdout_lines),
            stderr="".join(stderr_lines),
        )
        if check and not result.ok:
            raise CommandError(command, exit_code, result.stdout, result.stderr)
        return result

    def download_file(self, remote_path: str, local_path: str) -> None:
        if self._client is None:
            raise RuntimeError("Not connected - call connect() first")
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        sftp = self._client.open_sftp()
        try:
            sftp.get(remote_path, local_path)
            logger.info("Downloaded %s -> %s", remote_path, local_path)
        finally:
            sftp.close()

    def path_exists(self, remote_path: str) -> bool:
        result = self.run(f"test -e {remote_path}", check=False)
        return result.ok

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "SSHClient":
        self.connect(retries=3, retry_wait=5)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
