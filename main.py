"""SBOM Security — CLI entry point.

Commands:
  generate         Generate a CycloneDX SBOM for a project.
  list-components  List resolved components in a table (or JSON).
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from core import __version__, cyclonedx, spdx
from core.banner import render_banner
from core.engine import SbomGenerator
from core.logger import configure_logging
from core.models import SEVERITY_ORDER, VulnSeverity

console = Console()


@click.group(invoke_without_command=True)
@click.option("--log-level", default="WARNING")
@click.option("--no-banner", is_flag=True, default=False, help="Suppress the startup banner.")
@click.version_option(__version__, "-V", "--version", prog_name="sbom-security")
@click.pass_context
def cli(ctx: click.Context, log_level: str, no_banner: bool) -> None:
    """Generate SBOMs and analyze software supply-chain risk."""
    configure_logging(log_level)
    if ctx.invoked_subcommand is None:
        if not no_banner:
            render_banner(console)
        click.echo(ctx.get_help())


@cli.command("generate")
@click.option("--path", default=".", help="Project directory (or a single manifest file).")
@click.option("-o", "--output", default=None, help="Write SBOM here (default: stdout).")
@click.option("--format", "fmt", type=click.Choice(["cyclonedx", "spdx"]), default="cyclonedx",
              help="SBOM format (default: cyclonedx).")
@click.option("--app-name", default=None, help="Name for the SBOM's root component.")
def generate(path: str, output: str | None, fmt: str, app_name: str | None) -> None:
    """Generate an SBOM (CycloneDX or SPDX) for PATH."""
    sbom = SbomGenerator().generate(path)
    serializer = spdx if fmt == "spdx" else cyclonedx
    text = serializer.dumps(sbom, app_name=app_name)
    if output:
        from pathlib import Path
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        console.print(f"[green]{fmt} SBOM written:[/] {out} "
                      f"({sbom.count} components across {len(sbom.by_ecosystem())} ecosystem(s))")
    else:
        click.echo(text)


@cli.command("audit")
@click.option("--path", default=".", help="Project directory to scan.")
@click.option("--timeout", type=float, default=20.0, help="OSV API timeout (seconds).")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "cyclonedx"]),
              default="table")
@click.option("--fail-on", type=click.Choice([s.value for s in VulnSeverity]), default=None,
              help="Exit 1 if any vulnerability is at/above this severity (CI gate).")
def audit(path: str, timeout: float, fmt: str, fail_on: str | None) -> None:
    """Generate an SBOM for PATH, then correlate components with OSV vulnerabilities."""
    from core.osv import OSVClient, run_audit

    sbom = SbomGenerator().generate(path)
    ok = run_audit(sbom.components, OSVClient(timeout=timeout))
    if not ok:
        console.print("[yellow]OSV query failed (offline?) — results may be incomplete.[/]")

    findings = [(c, v) for c in sbom.components for v in c.vulnerabilities]

    if fmt == "cyclonedx":
        click.echo(cyclonedx.dumps(sbom))
    elif fmt == "json":
        console.print_json(data={
            "root": sbom.root,
            "components": sbom.count,
            "vulnerable_components": sum(1 for c in sbom.components if c.vulnerabilities),
            "vulnerabilities": len(findings),
            "by_severity": _vuln_severity_counts(findings),
            "findings": [{
                "component": c.name, "version": c.version, "ecosystem": c.ecosystem,
                "purl": c.purl, "id": v.id, "severity": v.severity.value, "cvss": v.cvss,
                "fixed": v.fixed, "summary": v.summary, "reference": v.reference,
            } for c, v in findings],
        })
    else:
        if findings:
            table = Table("Severity", "CVSS", "Component", "Vulnerability", "Fixed in",
                          title=f"Vulnerabilities — {len(findings)} in {sum(1 for c in sbom.components if c.vulnerabilities)} component(s)")
            for c, v in sorted(findings, key=lambda cv: -SEVERITY_ORDER[cv[1].severity]):
                table.add_row(_sev_style(v.severity), f"{v.cvss:.1f}" if v.cvss else "-",
                              f"{c.name} {c.version}", v.id, ", ".join(v.fixed) or "-")
            console.print(table)
        else:
            console.print("[green]No known vulnerabilities found.[/]")
        console.print(f"[dim]{sbom.count} components audited[/]")

    if fail_on:
        threshold = SEVERITY_ORDER[VulnSeverity(fail_on)]
        if any(SEVERITY_ORDER[v.severity] >= threshold for _, v in findings):
            console.print(f"[red]Gate failed:[/] vulnerability at/above {fail_on}.")
            raise SystemExit(1)


def _vuln_severity_counts(findings) -> dict[str, int]:
    counts: dict[str, int] = {}
    for _, v in findings:
        counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
    return counts


_VULN_STYLE = {
    VulnSeverity.CRITICAL: "[bold red]critical[/]", VulnSeverity.HIGH: "[red]high[/]",
    VulnSeverity.MEDIUM: "[yellow]medium[/]", VulnSeverity.LOW: "[cyan]low[/]",
    VulnSeverity.NONE: "[dim]none[/]", VulnSeverity.UNKNOWN: "[dim]unknown[/]",
}


def _sev_style(sev: VulnSeverity) -> str:
    return _VULN_STYLE.get(sev, sev.value)


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
