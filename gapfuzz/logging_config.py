"""Logging setup for GapFuzz."""

from __future__ import annotations

import logging
import sys


def configure(level: str = "INFO") -> None:
    """Configure root logging once."""
    numeric = getattr(logging, level.upper(), None)
    if not isinstance(numeric, int):
        raise ValueError(f"Invalid log level: {level!r}")
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric)
    # Keep aiohttp and others at WARNING to avoid log spam.
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
