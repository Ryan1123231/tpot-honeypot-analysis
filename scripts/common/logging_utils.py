"""Shared logging setup so every script in this repo logs the same way:
timestamped, leveled, to both stderr and a per-script rotating file under logs/.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Configure logging for an entrypoint script and return its logger.

    Handlers are attached to the ROOT logger (not just `name`'s logger) so
    that submodules using plain `logging.getLogger("log_parsing")` etc.
    (ssh_client, log_parsing, geolocation) propagate into the same stdout
    stream and the same per-run log file, instead of being silently dropped
    for lack of any handler.
    """
    root = logging.getLogger()
    if not root.handlers:
        root.setLevel(level)
        fmt = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(fmt)
        root.addHandler(stream_handler)

        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                LOG_DIR / f"{name}.log", maxBytes=5 * 1024 * 1024, backupCount=3
            )
            file_handler.setFormatter(fmt)
            root.addHandler(file_handler)
        except OSError:
            # Read-only filesystem (e.g. some CI containers) - stdout logging is enough.
            root.warning("Could not create log file under %s; logging to stdout only", LOG_DIR)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger
