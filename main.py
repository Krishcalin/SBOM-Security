"""SBOM Security — CLI entry point.

Commands:
  generate         Generate a CycloneDX SBOM for a project.
  list-components  List resolved components in a table (or JSON).
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from core.cyclonedx import dumps
from core.engine import SbomGenerator
from core.logger import configure_logging

console = Console()


@click.group()
@click.option("--log-level", default="WARNING")
def cli(log_level: str) -> None:
    """Generate SBOMs and analyze software supply-chain risk."""
    configure_logging(log_level)


@cli.command("generate")
@click.option("--path", default=".", help="Project directory (or a single manifest file).")
@click.option("-o", "--output", default=None, help="Write SBOM here (default: stdout).")
@click.option("--app-name", default=None, help="Name for the SBOM's root component.")
def generate(path: str, output: str | None, app_name: str | None) -> None:
    """Generate a CycloneDX SBOM for PATH."""
    sbom = SbomGenerator().generate(path)
    text = dumps(sbom, app_name=app_name)
    if output:
        from pathlib import Path
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        console.print(f"[green]SBOM written:[/] {out} "
                      f"({sbom.count} components across {len(sbom.by_ecosystem())} ecosystem(s))")
    else:
        click.echo(text)


@cli.command("list-components")
@click.option("--path", default=".", help="Project directory to scan.")
@click.option("--ecosystem", default=None, help="Filter to one ecosystem (pypi/npm/...).")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def list_components(path: str, ecosystem: str | None, fmt: str) -> None:
    """List the components discovered in PATH."""
    sbom = SbomGenerator().generate(path)
    comps = [c for c in sbom.components if not ecosystem or c.ecosystem == ecosystem]

    if fmt == "json":
        console.print_json(data={
            "root": sbom.root,
            "count": len(comps),
            "by_ecosystem": sbom.by_ecosystem(),
            "components": [{"ecosystem": c.ecosystem, "name": c.name, "version": c.version,
                            "purl": c.purl, "direct": c.direct, "scope": c.scope}
                           for c in comps],
        })
        return

    if not comps:
        console.print("[yellow]No components found.[/]")
        return
    table = Table("Ecosystem", "Name", "Version", "purl",
                  title=f"Components — {len(comps)}")
    for c in comps:
        table.add_row(c.ecosystem, c.name, c.version, c.purl)
    console.print(table)
    eco = ", ".join(f"{k}: {v}" for k, v in sorted(sbom.by_ecosystem().items()))
    console.print(f"[dim]{eco}[/]")


if __name__ == "__main__":
    cli()
