"""BaseParser — the contract every ecosystem parser implements.

A parser declares which filenames it understands (`matches`) and turns one such
file into a list of `Component`s (`parse`). Working at file granularity lets the
engine walk a project tree and dispatch each manifest/lockfile to the right parser.
Prefer lockfiles (exact, resolved versions) over manifests (ranges) when both exist.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from core.models import Component


class BaseParser(ABC):
    ECOSYSTEM: str = ""
    PARSER_ID: str = "base"
    FILENAMES: tuple[str, ...] = ()

    def matches(self, path: Path) -> bool:
        return path.name in self.FILENAMES

    @abstractmethod
    def parse(self, path: Path) -> list[Component]:
        """Return the components declared in this file."""
        raise NotImplementedError
