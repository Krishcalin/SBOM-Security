"""Startup banner for the CLI.

Rendered on bare invocation (and never to stdout during `generate`, so piped SBOM
output stays clean).
"""

from __future__ import annotations

from rich.console import Console

from core import __version__

# ANSI Shadow "SBOM"
_ASCII = r"""
███████╗██████╗  ██████╗ ███╗   ███╗
██╔════╝██╔══██╗██╔═══██╗████╗ ████║
███████╗██████╔╝██║   ██║██╔████╔██║
╚════██║██╔══██╗██║   ██║██║╚██╔╝██║
███████║██████╔╝╚██████╔╝██║ ╚═╝ ██║
╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝
"""

_TAGLINE = "Software Bill of Materials  ·  Supply-Chain Security"


def render_banner(console: Console | None = None) -> None:
    console = console or Console()
    console.print(f"[bold cyan]{_ASCII.strip(chr(10))}[/]")
    console.print(
        f"  [bold white]SBOM Security[/] [dim]v{__version__}[/]  "
        f"[cyan]CycloneDX & SPDX SBOMs · vuln correlation · dependency drift[/]"
    )
    console.print(f"  [dim]{_TAGLINE}[/]")
    console.print(f"  [dim]Python · Node · Maven · Go[/]\n")
