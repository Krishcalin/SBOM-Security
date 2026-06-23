"""Structured logging setup (structlog)."""

from __future__ import annotations

import logging

import structlog


def configure_logging(level: str = "WARNING") -> None:
    lvl = getattr(logging, level.upper(), logging.WARNING)
    logging.basicConfig(format="%(message)s", level=lvl)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(lvl),
    )


def get_logger(name: str = "sbom-security") -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
