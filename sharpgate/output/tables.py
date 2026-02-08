"""Rich table formatters for delegation information display."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sharpgate.analyser.models import (
    AccountType,
    AttackPath,
    DelegationFinding,
    DelegationType,
    ProtectedAccount,
    Severity,
)


def delegation_summary_table(findings: list[DelegationFinding]) -> Table:
    """Create a summary table of all discovered delegation configurations."""
    table = Table(
        title="Delegation Findings",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
    )

    table.add_column("Account", style="bold white")
    table.add_column("Type", justify="center")
    table.add_column("Delegation", justify="center")
    table.add_column("Target SPNs / Principals", style="dim")
    table.add_column("DC?", justify="center")
    table.add_column("Paths", justify="center")

    for finding in findings:
        deleg_text = _delegation_styled(finding.delegation_type)
        type_text = _account_type_styled(finding.account_type)
        dc_text = "[red]DC[/red]" if finding.is_dc else "[dim]-[/dim]"

        # Target info depends on delegation type
        if finding.delegation_type == DelegationType.RBCD:
            targets = ", ".join(
                p.samaccountname or p.sid for p in finding.rbcd_principals
            )
            if not targets:
                targets = "[dim]unknown[/dim]"
        elif finding.delegation_type == DelegationType.UNCONSTRAINED:
            targets = "[bold]*ANY SERVICE*[/bold]"
        else:
            targets = finding.spn_summary or "[dim]none[/dim]"

        # Truncate long SPN lists
        if len(targets) > 60:
            targets = targets[:57] + "..."

        critical_count = sum(
            1 for p in finding.attack_paths if p.severity == Severity.CRITICAL
        )
        high_count = sum(
            1 for p in finding.attack_paths if p.severity == Severity.HIGH
        )
        path_summary = ""
        if critical_count:
            path_summary += f"[red]{critical_count} CRIT[/red] "
        if high_count:
            path_summary += f"[yellow]{high_count} HIGH[/yellow]"
        if not path_summary:
            total = sum(
                1 for p in finding.attack_paths if p.severity != Severity.INFO
            )
            path_summary = f"[dim]{total}[/dim]" if total else "[dim]-[/dim]"

        table.add_row(
            finding.samaccountname,
            type_text,
            deleg_text,
            targets,
            dc_text,
            path_summary,
        )

    return table


def finding_detail_panel(finding: DelegationFinding) -> Panel:
    """Create a detailed panel for a single delegation finding."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Property", style="bold cyan", width=20)
    table.add_column("Value")

    table.add_row("Account", finding.samaccountname)
    table.add_row("DN", f"[dim]{finding.dn}[/dim]")
    table.add_row("Account Type", finding.account_type.value)
    table.add_row(
        "Delegation Type",
        _delegation_styled(finding.delegation_type) if finding.delegation_type else "[dim]None[/dim]",
    )
    table.add_row("Domain Controller", "[red]Yes[/red]" if finding.is_dc else "No")
    table.add_row("Enabled", "[green]Yes[/green]" if finding.is_enabled else "[red]Disabled[/red]")
    table.add_row("adminCount", f"[yellow]{finding.admin_count}[/yellow]" if finding.admin_count else "[dim]0[/dim]")
    table.add_row("UAC", f"0x{finding.uac:X}")

    if finding.has_protocol_transition:
        table.add_row("Protocol Transition", "[red]ENABLED (T2A4D)[/red]")

    if finding.allowed_services:
        spn_lines = "\n".join(f"  {s.raw_spn}" for s in finding.allowed_services)
        table.add_row("Allowed SPNs", spn_lines)

    if finding.rbcd_principals:
        principal_lines = "\n".join(
            f"  {p.samaccountname or p.sid}" for p in finding.rbcd_principals
        )
        table.add_row("RBCD Principals", principal_lines)

    deleg_label = finding.delegation_type.short if finding.delegation_type else "UNKNOWN"
    title = f"{finding.samaccountname}  [{deleg_label}]"
    return Panel(table, title=title, border_style="blue", expand=True)


def attack_paths_panel(finding: DelegationFinding) -> Panel | None:
    """Create a panel showing attack paths for a finding."""
    if not finding.attack_paths:
        return None

    lines: list[Text] = []
    for path in finding.attack_paths:
        severity_color = path.severity.color
        line = Text()
        line.append(f"  [{path.severity.value}] ", style=f"bold {severity_color}")
        line.append(path.name, style=f"bold {severity_color}")
        lines.append(line)

        desc_line = Text()
        desc_line.append(f"    {path.description}", style="dim")
        lines.append(desc_line)

        if path.prerequisites:
            for prereq in path.prerequisites:
                prereq_line = Text()
                prereq_line.append("    Requires: ", style="bold dim")
                prereq_line.append(prereq, style="dim")
                lines.append(prereq_line)

        if path.commands_key:
            cmd_line = Text()
            cmd_line.append("    -> Commands generated below", style="italic green")
            lines.append(cmd_line)

        lines.append(Text(""))

    content = Text("\n").join(lines)
    return Panel(
        content,
        title="Attack Paths",
        border_style="red",
        expand=True,
    )


def command_block_panel(
    attack_name: str,
    finding: DelegationFinding,
    tool_name: str,
    steps: list[dict],
    platform: str,
) -> Panel:
    """Create a panel for a command block."""
    lines = []
    for step in steps:
        step_num = step.get("step", "")
        title = step.get("title", "")
        command = step.get("command", "")
        prereq = step.get("prereq", "")
        notes = step.get("notes", [])

        if step_num:
            lines.append(f"[bold cyan]Step {step_num}:[/bold cyan] {title}")
        else:
            lines.append(f"[bold cyan]{title}[/bold cyan]")

        if prereq:
            lines.append(f"  [dim]Prereq: {prereq}[/dim]")

        lines.append("")
        for cmd_line in command.split("\n"):
            if cmd_line.strip().startswith("#"):
                lines.append(f"  [dim]{cmd_line}[/dim]")
            else:
                lines.append(f"  [bold green]{cmd_line}[/bold green]")
        lines.append("")

        for note in notes:
            lines.append(f"  [dim italic]Note: {note}[/dim italic]")

        lines.append("")

    content = "\n".join(lines)
    platform_icon = "Linux" if platform == "linux" else "Windows"
    panel_title = f"{attack_name} [{tool_name}] ({platform_icon})"
    return Panel(content, title=panel_title, border_style="green", expand=True)


def protected_accounts_panel(
    protected_users: list[ProtectedAccount],
    not_delegated: list[ProtectedAccount],
) -> Panel | None:
    """Create a panel showing accounts protected from delegation."""
    if not protected_users and not not_delegated:
        return None

    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=None,
        padding=(0, 2),
    )
    table.add_column("Account", style="bold white")
    table.add_column("Protection", justify="center")
    table.add_column("Admin", justify="center")

    for acct in protected_users:
        admin_text = "[yellow]Yes[/yellow]" if acct.is_admin else "[dim]No[/dim]"
        table.add_row(acct.samaccountname, "[green]Protected Users[/green]", admin_text)

    for acct in not_delegated:
        admin_text = "[yellow]Yes[/yellow]" if acct.is_admin else "[dim]No[/dim]"
        table.add_row(acct.samaccountname, "[green]NOT_DELEGATED[/green]", admin_text)

    return Panel(
        table,
        title="Protected Accounts (Delegation-Resistant)",
        border_style="green",
        expand=True,
    )


def _delegation_styled(deleg_type: DelegationType | None) -> str:
    """Style a delegation type for display."""
    if deleg_type is None:
        return "[dim]Unknown[/dim]"
    return f"[{deleg_type.color}]{deleg_type.short}[/{deleg_type.color}]"


def _account_type_styled(account_type: AccountType) -> str:
    """Style an account type for display."""
    colors = {
        AccountType.COMPUTER: "cyan",
        AccountType.USER: "yellow",
        AccountType.MANAGED_SERVICE: "magenta",
        AccountType.UNKNOWN: "dim",
    }
    color = colors.get(account_type, "dim")
    return f"[{color}]{account_type.value}[/{color}]"
