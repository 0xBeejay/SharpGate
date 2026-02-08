"""ASCII delegation chain map renderer."""

from __future__ import annotations

from rich.panel import Panel

from sharpgate.analyser.models import DelegationFinding, DelegationType, Severity


def render_delegation_map(
    domain: str,
    findings: list[DelegationFinding],
) -> Panel:
    """Render an ASCII diagram showing delegation relationships grouped by type.

    Example output:
        [UNCONSTRAINED]
          WEBSERVER$  --[UNCONSTRAINED]--  *ANY SERVICE*     CRITICAL
          DC01$       --[UNCONSTRAINED]--  *ANY SERVICE*     (Domain Controller)

        [CONSTRAINED]
          SQLSERVER$  --[CONSTRAINED+T2A4D]-->  CIFS/FILESERVER, HTTP/PORTAL    CRITICAL
          APPSVC$     --[CONSTRAINED]-->  MSSQLSvc/DB01:1433                    HIGH

        [RBCD]
          FILESERVER$ <--[RBCD]--  EVIL$, APPSVC$                               HIGH
    """
    if not findings:
        return Panel(
            "[dim]No delegation configurations found.[/dim]",
            title="Delegation Map",
            border_style="blue",
        )

    lines: list[str] = [""]

    # Group by delegation type
    unconstrained = [f for f in findings if f.delegation_type == DelegationType.UNCONSTRAINED]
    constrained_t2a4d = [f for f in findings if f.delegation_type == DelegationType.CONSTRAINED_T2A4D]
    constrained = [f for f in findings if f.delegation_type == DelegationType.CONSTRAINED]
    rbcd = [f for f in findings if f.delegation_type == DelegationType.RBCD]

    if unconstrained:
        lines.append("  [bold red][UNCONSTRAINED][/bold red]")
        for f in unconstrained:
            severity = _get_max_severity(f)
            sev_str = _severity_tag(severity, f.is_dc)
            name = f"  {f.samaccountname:<20}"
            lines.append(
                f"  {name}  [red]──[UNCONSTRAINED]──[/red]  "
                f"[bold]*ANY SERVICE*[/bold]"
                f"     {sev_str}"
            )
        lines.append("")

    if constrained_t2a4d:
        lines.append("  [bold red][CONSTRAINED + T2A4D][/bold red]")
        for f in constrained_t2a4d:
            severity = _get_max_severity(f)
            sev_str = _severity_tag(severity, f.is_dc)
            name = f"  {f.samaccountname:<20}"
            spns = _truncate_spns(f)
            lines.append(
                f"  {name}  [red]──[CONSTRAINED+T2A4D]──►[/red]  "
                f"{spns}"
                f"     {sev_str}"
            )
        lines.append("")

    if constrained:
        lines.append("  [bold yellow][CONSTRAINED][/bold yellow]")
        for f in constrained:
            severity = _get_max_severity(f)
            sev_str = _severity_tag(severity, f.is_dc)
            name = f"  {f.samaccountname:<20}"
            spns = _truncate_spns(f)
            lines.append(
                f"  {name}  [yellow]──[CONSTRAINED]──►[/yellow]  "
                f"{spns}"
                f"     {sev_str}"
            )
        lines.append("")

    if rbcd:
        lines.append("  [bold blue][RBCD][/bold blue]")
        for f in rbcd:
            severity = _get_max_severity(f)
            sev_str = _severity_tag(severity, f.is_dc)
            name = f"  {f.samaccountname:<20}"
            principals = ", ".join(
                p.samaccountname or p.sid for p in f.rbcd_principals
            )
            if len(principals) > 50:
                principals = principals[:47] + "..."
            lines.append(
                f"  {name}  [blue]◄──[RBCD]──[/blue]  "
                f"{principals}"
                f"     {sev_str}"
            )
        lines.append("")

    content = "\n".join(lines)
    return Panel(
        content,
        title=f"[bold cyan]Delegation Map - {domain.upper()}[/bold cyan]",
        border_style="cyan",
        expand=True,
    )


def _get_max_severity(finding: DelegationFinding) -> Severity:
    """Get the highest severity from a finding's attack paths."""
    priority = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for sev in priority:
        if any(p.severity == sev for p in finding.attack_paths):
            return sev
    return Severity.INFO


def _severity_tag(severity: Severity, is_dc: bool) -> str:
    """Format a severity tag for the diagram."""
    if is_dc and severity == Severity.INFO:
        return "[dim](Domain Controller)[/dim]"
    return f"[{severity.color}]{severity.value}[/{severity.color}]"


def _truncate_spns(finding: DelegationFinding) -> str:
    """Format SPN list, truncating if too long."""
    spns = ", ".join(s.raw_spn for s in finding.allowed_services)
    if len(spns) > 50:
        spns = spns[:47] + "..."
    return spns
