"""Command generation dispatcher - selects the right commands per attack path."""

from __future__ import annotations

from dataclasses import dataclass, field

from sharpgate.analyser.models import AttackPath, DelegationFinding
from sharpgate.commands.impacket_cmds import IMPACKET_COMMANDS
from sharpgate.commands.mimikatz_cmds import MIMIKATZ_COMMANDS
from sharpgate.commands.other_cmds import OTHER_COMMANDS
from sharpgate.commands.rubeus_cmds import RUBEUS_COMMANDS


@dataclass
class CommandBlock:
    """A block of commands for a specific tool."""
    tool_name: str
    steps: list[dict] = field(default_factory=list)


@dataclass
class AttackCommands:
    """All command variants for an attack path."""
    attack_path: AttackPath
    finding: DelegationFinding
    linux_commands: list[CommandBlock] = field(default_factory=list)
    windows_commands: list[CommandBlock] = field(default_factory=list)


def generate_commands(
    finding: DelegationFinding,
    toolset: str = "all",
) -> list[AttackCommands]:
    """Generate commands for all attack paths on a finding.

    Args:
        finding: DelegationFinding with attack_paths populated
        toolset: "linux", "windows", or "all"

    Returns:
        List of AttackCommands, one per attack path
    """
    results = []

    for path in finding.attack_paths:
        if not path.commands_key:
            results.append(AttackCommands(
                attack_path=path,
                finding=finding,
            ))
            continue

        cmds = AttackCommands(
            attack_path=path,
            finding=finding,
        )

        key = path.commands_key

        if toolset in ("linux", "all"):
            cmds.linux_commands = _get_linux_commands(key, finding)

        if toolset in ("windows", "all"):
            cmds.windows_commands = _get_windows_commands(key, finding)

        results.append(cmds)

    return results


def _get_linux_commands(key: str, finding: DelegationFinding) -> list[CommandBlock]:
    """Get Linux toolset commands for a given key."""
    blocks = []

    if key in IMPACKET_COMMANDS:
        steps = IMPACKET_COMMANDS[key](finding)
        blocks.append(CommandBlock(tool_name="Impacket", steps=steps))

    other_key_map = {
        "unconstrained_coerce": "unconstrained_krbrelayx",
        "rbcd_setup": "rbcd_setup_linux",
    }
    other_key = other_key_map.get(key, key)
    if other_key in OTHER_COMMANDS:
        steps = OTHER_COMMANDS[other_key](finding)
        blocks.append(CommandBlock(
            tool_name=_tool_name_from_key(other_key),
            steps=steps,
        ))

    return blocks


def _get_windows_commands(key: str, finding: DelegationFinding) -> list[CommandBlock]:
    """Get Windows toolset commands for a given key."""
    blocks = []

    if key in RUBEUS_COMMANDS:
        steps = RUBEUS_COMMANDS[key](finding)
        blocks.append(CommandBlock(tool_name="Rubeus", steps=steps))

    if key in MIMIKATZ_COMMANDS:
        steps = MIMIKATZ_COMMANDS[key](finding)
        blocks.append(CommandBlock(tool_name="Mimikatz", steps=steps))

    other_key_map = {
        "unconstrained_coerce": "unconstrained_spoolsample",
        "rbcd_setup": "rbcd_setup_powerview",
    }
    other_key = other_key_map.get(key, key)
    if other_key in OTHER_COMMANDS:
        steps = OTHER_COMMANDS[other_key](finding)
        blocks.append(CommandBlock(
            tool_name=_tool_name_from_key(other_key),
            steps=steps,
        ))

    return blocks


def _tool_name_from_key(key: str) -> str:
    """Derive a display tool name from an OTHER_COMMANDS key."""
    name_map = {
        "unconstrained_krbrelayx": "krbrelayx",
        "unconstrained_spoolsample": "SpoolSample",
        "rbcd_setup_linux": "rbcd.py / addcomputer.py",
        "rbcd_setup_powerview": "PowerView / StandIn",
    }
    return name_map.get(key, key)
