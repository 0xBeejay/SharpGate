"""Main output orchestrator - coordinates diagram, tables, and commands."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from sharpgate.analyser.models import (
    DelegationFinding,
    DelegationType,
    ProtectedAccount,
    Severity,
)
from sharpgate.commands.generator import AttackCommands, generate_commands
from sharpgate.output.diagram import render_delegation_map
from sharpgate.output.tables import (
    attack_paths_panel,
    command_block_panel,
    delegation_summary_table,
    finding_detail_panel,
    protected_accounts_panel,
)


class SharpGateOutput:
    """Orchestrates the full output flow: banner -> diagram -> tables -> commands."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def print_banner(self, domain: str):
        """Print the SharpGate banner."""
        banner = Text()
        banner.append("SHARPGATE", style="bold red")
        banner.append(" v1.0", style="dim")
        banner.append("  |  Mapping delegation for ", style="dim")
        banner.append(domain.upper(), style="bold yellow")

        self.console.print()
        self.console.print(Panel(banner, border_style="red", expand=True))
        self.console.print()

    def print_no_findings(self, domain: str):
        """Print message when no delegation is found."""
        self.console.print(
            f"[yellow]No delegation configurations found in {domain.upper()}.[/yellow]"
        )
        self.console.print(
            "[dim]No unconstrained, constrained, or RBCD delegation detected.[/dim]"
        )

    def print_results(
        self,
        domain: str,
        findings: list[DelegationFinding],
        protected_users: list[ProtectedAccount] | None = None,
        not_delegated: list[ProtectedAccount] | None = None,
        toolset: str = "all",
        focus_account: str | None = None,
        focus_type: str | None = None,
    ):
        """Print the full analysis results.

        Args:
            domain: The domain we enumerated
            findings: List of analysed DelegationFinding objects
            protected_users: Protected Users group members
            not_delegated: Accounts with NOT_DELEGATED flag
            toolset: "linux", "windows", or "all"
            focus_account: If set, only show this specific account
            focus_type: If set, filter by delegation type
        """
        if not findings:
            self.print_no_findings(domain)
            return

        display_findings = findings

        # Filter by account
        if focus_account:
            display_findings = [
                f for f in display_findings
                if f.samaccountname.upper() == focus_account.upper()
            ]
            if not display_findings:
                self.console.print(
                    f"[red]Account {focus_account} not found in delegation results.[/red]"
                )
                self.console.print("[dim]Accounts found:[/dim]")
                for f in findings:
                    self.console.print(f"  - {f.samaccountname}")
                return

        # Filter by type
        if focus_type:
            type_map = {
                "unconstrained": DelegationType.UNCONSTRAINED,
                "constrained": None,  # Matches both constrained variants
                "rbcd": DelegationType.RBCD,
            }
            target_type = type_map.get(focus_type.lower())
            if focus_type.lower() == "constrained":
                display_findings = [
                    f for f in display_findings
                    if f.delegation_type in (
                        DelegationType.CONSTRAINED,
                        DelegationType.CONSTRAINED_T2A4D,
                    )
                ]
            elif target_type:
                display_findings = [
                    f for f in display_findings
                    if f.delegation_type == target_type
                ]

        if not display_findings:
            self.console.print(
                f"[yellow]No delegation findings match the filter.[/yellow]"
            )
            return

        # 1. Delegation Map Diagram
        self.console.print(render_delegation_map(domain, display_findings))
        self.console.print()

        # 2. Summary Table
        self.console.print(delegation_summary_table(display_findings))
        self.console.print()

        # 3. Protected accounts (if collected)
        if protected_users or not_delegated:
            prot_panel = protected_accounts_panel(
                protected_users or [], not_delegated or [],
            )
            if prot_panel:
                self.console.print(prot_panel)
                self.console.print()

        # 4. Detailed panels and commands for each finding
        for finding in display_findings:
            self._print_finding_detail(finding, toolset)

    def _print_finding_detail(self, finding: DelegationFinding, toolset: str):
        """Print detailed analysis for a single finding."""
        self.console.print(finding_detail_panel(finding))

        paths_panel = attack_paths_panel(finding)
        if paths_panel:
            self.console.print(paths_panel)

        if finding.attack_paths:
            all_commands = generate_commands(finding, toolset=toolset)
            self._print_commands(all_commands, toolset)

        self.console.print()

    def _print_commands(self, all_commands: list[AttackCommands], toolset: str):
        """Print command blocks for all attack paths."""
        for attack_cmds in all_commands:
            path = attack_cmds.attack_path
            if not path.commands_key:
                continue

            self.console.print(
                Rule(
                    f"Commands: {path.name} ({attack_cmds.finding.samaccountname})",
                    style=path.severity.color,
                )
            )

            if toolset in ("linux", "all") and attack_cmds.linux_commands:
                for block in attack_cmds.linux_commands:
                    self.console.print(command_block_panel(
                        attack_name=path.name,
                        finding=attack_cmds.finding,
                        tool_name=block.tool_name,
                        steps=block.steps,
                        platform="linux",
                    ))

            if toolset in ("windows", "all") and attack_cmds.windows_commands:
                for block in attack_cmds.windows_commands:
                    self.console.print(command_block_panel(
                        attack_name=path.name,
                        finding=attack_cmds.finding,
                        tool_name=block.tool_name,
                        steps=block.steps,
                        platform="windows",
                    ))

    def print_error(self, message: str):
        """Print an error message."""
        self.console.print(f"[bold red]Error:[/bold red] {message}")

    def print_info(self, message: str):
        """Print an info message."""
        self.console.print(f"[dim]{message}[/dim]")

    def print_section(self, title: str):
        """Print a section header."""
        self.console.print()
        self.console.print(Rule(title, style="cyan"))
        self.console.print()

    def print_collector_status(self, name: str, count: int):
        """Print status for a collector run."""
        if count > 0:
            self.console.print(
                f"  [green]+[/green] {name}: [bold]{count}[/bold] results"
            )
        else:
            self.console.print(
                f"  [dim]-[/dim] {name}: [dim]none found[/dim]"
            )
