"""Attack path engine - determines exploitable paths per delegation type."""

from __future__ import annotations

from sharpgate.analyser.models import (
    AccountType,
    AttackPath,
    DelegationFinding,
    DelegationType,
    Severity,
)
from sharpgate.analyser.spn_analysis import analyse_spn_targets


def analyse_paths(
    finding: DelegationFinding,
    dc_hostnames: list[str] | None = None,
) -> DelegationFinding:
    """Determine attack paths for a single delegation finding.

    Args:
        finding: Classified delegation finding
        dc_hostnames: Known DC hostnames for SPN target analysis

    Returns:
        The finding with attack_paths populated
    """
    if dc_hostnames is None:
        dc_hostnames = []

    finding.attack_paths = []

    if finding.delegation_type == DelegationType.UNCONSTRAINED:
        _analyse_unconstrained(finding)
    elif finding.delegation_type == DelegationType.CONSTRAINED_T2A4D:
        _analyse_constrained_t2a4d(finding, dc_hostnames)
    elif finding.delegation_type == DelegationType.CONSTRAINED:
        _analyse_constrained(finding, dc_hostnames)
    elif finding.delegation_type == DelegationType.RBCD:
        _analyse_rbcd(finding)

    # Common enrichments
    _check_admin_count(finding)

    return finding


def analyse_all_paths(
    findings: list[DelegationFinding],
    dc_hostnames: list[str] | None = None,
) -> list[DelegationFinding]:
    """Analyse attack paths for all findings."""
    if dc_hostnames is None:
        dc_hostnames = []
    for finding in findings:
        analyse_paths(finding, dc_hostnames)
    return findings


def _analyse_unconstrained(finding: DelegationFinding):
    """Attack paths for unconstrained delegation."""
    if finding.is_dc:
        finding.attack_paths.append(AttackPath(
            name="Unconstrained Delegation (Domain Controller)",
            severity=Severity.INFO,
            description=(
                f"{finding.samaccountname} is a DC with unconstrained delegation. "
                "This is the default configuration. Note: a compromised DC with "
                "unconstrained delegation can be used to coerce OTHER DCs for "
                "lateral movement across the domain."
            ),
            notes=[
                "DCs have TRUSTED_FOR_DELEGATION by default.",
                "Consider coercing authentication from other DCs to this one.",
            ],
        ))
    elif finding.account_type == AccountType.USER:
        finding.attack_paths.append(AttackPath(
            name="Unconstrained Delegation - User Account",
            severity=Severity.CRITICAL,
            description=(
                f"{finding.samaccountname} is a USER account with unconstrained "
                "delegation. TGTs are NOT cached on a user object — you cannot "
                "run Rubeus monitor or coerce auth TO a user. Instead: identify "
                "the host where this account's service runs (via its SPNs), "
                "compromise that host, and extract TGTs from LSASS memory on "
                "that host. Alternatively, use the account's key with krbrelayx "
                "to relay coerced authentication."
            ),
            prerequisites=[
                f"Compromise {finding.samaccountname}'s credentials/hash",
                "Identify the host running this account's service (check SPNs)",
                "Local admin on the service host OR use krbrelayx with the account's key",
            ],
            notes=[
                "User accounts cannot receive coerced machine auth directly.",
                "The service host's LSASS holds TGTs for users authenticating to the service.",
                "krbrelayx.py with the user's AES key can capture delegated TGTs.",
                "Check SPNs with Get-DomainUser or GetUserSPNs to find the service host.",
            ],
            commands_key="unconstrained_coerce_user",
        ))
    else:
        finding.attack_paths.append(AttackPath(
            name="Unconstrained Delegation - TGT Capture",
            severity=Severity.CRITICAL,
            description=(
                f"{finding.samaccountname} has unconstrained delegation. Any user "
                "authenticating to this host will leave their TGT cached. Coerce "
                "DC authentication (PrinterBug/PetitPotam) to capture the DC's "
                "TGT and perform DCSync."
            ),
            prerequisites=[
                f"Compromise {finding.samaccountname} or its credentials",
                "Network access to coerce DC authentication",
            ],
            notes=[
                "PrinterBug (MS-RPRN) and PetitPotam (MS-EFSRPC) can force DC auth.",
                "Captured TGT enables DCSync for full domain compromise.",
                "krbrelayx.py can be used to capture and export the TGT.",
            ],
            commands_key="unconstrained_coerce",
        ))


def _analyse_constrained_t2a4d(
    finding: DelegationFinding,
    dc_hostnames: list[str],
):
    """Attack paths for constrained delegation with protocol transition."""
    spn_info = analyse_spn_targets(finding, dc_hostnames)

    if spn_info.get("targets_dc"):
        dc_svcs = spn_info.get("dc_services", [])
        dc_svc_str = ", ".join(s.raw_spn for s in dc_svcs)
        alt_access = spn_info.get("critical_access", [])
        alt_str = ", ".join(f"{s} on {h}" for h, s in alt_access) if alt_access else ""

        desc = (
            f"{finding.samaccountname} has constrained delegation with protocol "
            f"transition (T2A4D) to DC services: {dc_svc_str}. S4U2Self + S4U2Proxy "
            "allows impersonating ANY user (including Domain Admin) to these services "
            "without any client interaction. Domain compromise via DCSync."
        )
        if alt_str:
            desc += f" Alternative service name trick also provides: {alt_str}."

        finding.attack_paths.append(AttackPath(
            name="Constrained Delegation + T2A4D -> DC (Domain Compromise)",
            severity=Severity.CRITICAL,
            description=desc,
            prerequisites=[
                f"Compromise {finding.samaccountname} or its credentials/hash",
            ],
            notes=[
                "S4U2Self provides a forwardable service ticket without client interaction.",
                "S4U2Proxy forwards it to the allowed SPN.",
                "Alternative service name trick: rewrite SPN service type to LDAP for DCSync.",
                "No interaction from the impersonated user is required.",
            ],
            commands_key="constrained_t2a4d",
        ))
    else:
        spn_str = finding.spn_summary
        finding.attack_paths.append(AttackPath(
            name="Constrained Delegation + Protocol Transition (T2A4D)",
            severity=Severity.CRITICAL,
            description=(
                f"{finding.samaccountname} has constrained delegation with protocol "
                f"transition to: {spn_str}. Can impersonate ANY user to these "
                "services without client interaction via S4U2Self + S4U2Proxy."
            ),
            prerequisites=[
                f"Compromise {finding.samaccountname} or its credentials/hash",
            ],
            notes=[
                "Alternative service name trick may expand access beyond listed SPNs.",
                "If target host runs additional services, they may also be accessible.",
            ],
            commands_key="constrained_t2a4d",
        ))

    _add_spn_hostname_warning(finding)

    if finding.account_type == AccountType.USER:
        finding.attack_paths[-1].notes.append(
            f"{finding.samaccountname} is a USER account — its hash can be "
            "Kerberoasted if it has an SPN, or obtained via targeted credential "
            "attacks. No machine compromise needed to obtain the key."
        )


def _analyse_constrained(
    finding: DelegationFinding,
    dc_hostnames: list[str],
):
    """Attack paths for constrained delegation without protocol transition."""
    spn_info = analyse_spn_targets(finding, dc_hostnames)
    spn_str = finding.spn_summary

    if spn_info.get("targets_dc"):
        dc_svcs = spn_info.get("dc_services", [])
        dc_svc_str = ", ".join(s.raw_spn for s in dc_svcs)

        finding.attack_paths.append(AttackPath(
            name="Constrained Delegation -> DC (Requires Client TGT)",
            severity=Severity.HIGH,
            description=(
                f"{finding.samaccountname} has constrained delegation to DC services: "
                f"{dc_svc_str}. Requires a valid forwardable TGT from a client, then "
                "S4U2Proxy can forward it. Alternative service name trick may enable DCSync."
            ),
            prerequisites=[
                f"Compromise {finding.samaccountname} or its credentials",
                "Obtain a valid forwardable TGT (e.g. from unconstrained delegation host, "
                "or legitimate service interaction)",
            ],
            notes=[
                "Without T2A4D, S4U2Self does NOT produce a forwardable ticket.",
                "Need a real client TGT or additional ticket from another source.",
                "Alternative service name trick still applies to the forwarded ticket.",
            ],
            commands_key="constrained_no_t2a4d",
        ))
    else:
        finding.attack_paths.append(AttackPath(
            name="Constrained Delegation (Requires Client TGT)",
            severity=Severity.HIGH,
            description=(
                f"{finding.samaccountname} has constrained delegation to: {spn_str}. "
                "Requires a valid forwardable client TGT for S4U2Proxy."
            ),
            prerequisites=[
                f"Compromise {finding.samaccountname} or its credentials",
                "Obtain a valid forwardable TGT from a client",
            ],
            notes=[
                "Can be chained with unconstrained delegation for TGT capture.",
                "Alternative service name trick may expand access.",
            ],
            commands_key="constrained_no_t2a4d",
        ))

    _add_spn_hostname_warning(finding)


def _analyse_rbcd(finding: DelegationFinding):
    """Attack paths for resource-based constrained delegation."""
    principal_str = ", ".join(
        p.samaccountname or p.sid for p in finding.rbcd_principals
    )

    finding.attack_paths.append(AttackPath(
        name="RBCD - Existing Configuration",
        severity=Severity.HIGH,
        description=(
            f"{finding.samaccountname} allows delegation from: {principal_str}. "
            "If any of these accounts are compromised, S4U2Self + S4U2Proxy "
            "can be used to access any service on this target."
        ),
        prerequisites=[
            f"Compromise one of: {principal_str}",
        ],
        notes=[
            "RBCD uses S4U2Self + S4U2Proxy from the allowed principal.",
            "The principal does NOT need SPN set for S4U2Self in RBCD.",
            "Any service on the target is accessible (no SPN restriction).",
        ],
        commands_key="rbcd_existing",
    ))

    # Also note the setup attack path
    finding.attack_paths.append(AttackPath(
        name="RBCD - Setup Attack",
        severity=Severity.MEDIUM,
        description=(
            f"If you have write access to {finding.samaccountname}'s "
            "msDS-AllowedToActOnBehalfOfOtherIdentity attribute, you can add "
            "a controlled machine account and perform S4U to access this target."
        ),
        prerequisites=[
            f"Write access to {finding.samaccountname} (GenericAll, GenericWrite, "
            "WriteDacl, or WriteProperty on the attribute)",
            "Ability to add a machine account (default MachineAccountQuota = 10)",
        ],
        notes=[
            "addcomputer.py or StandIn can create the machine account.",
            "rbcd.py or PowerView can set the RBCD attribute.",
            "Then S4U2Self + S4U2Proxy from the new machine account.",
        ],
        commands_key="rbcd_setup",
    ))


def _check_admin_count(finding: DelegationFinding):
    """Add a note if the delegation account has adminCount=1."""
    if finding.admin_count > 0:
        finding.attack_paths.append(AttackPath(
            name="High-Value Delegation Account",
            severity=Severity.MEDIUM,
            description=(
                f"{finding.samaccountname} has adminCount=1, indicating it is or was "
                "a member of a privileged group. Delegation from privileged accounts "
                "increases the impact of compromise."
            ),
            notes=[
                "adminCount=1 is set by SDProp on accounts in privileged groups.",
                "This may indicate Domain Admin, Enterprise Admin, or similar.",
            ],
        ))


def _add_spn_hostname_warning(finding: DelegationFinding):
    """Warn if any allowed SPN uses an FQDN (hostname mismatch can break S4U2Proxy)."""
    fqdn_spns = [
        svc for svc in finding.allowed_services
        if "." in svc.hostname
    ]
    if not fqdn_spns:
        return

    short_spns = [
        svc for svc in finding.allowed_services
        if svc.hostname and "." not in svc.hostname
    ]

    if fqdn_spns and not short_spns:
        # All SPNs use FQDN — warn about possible short hostname requirement
        for path in finding.attack_paths:
            if path.commands_key:
                path.notes.append(
                    "SPN hostname mismatch: all SPNs use FQDN. If S4U2Proxy fails "
                    "with KDC_ERR_BADOPTION or STATUS_MORE_PROCESSING_REQUIRED, "
                    "try the short hostname (e.g. HOST/SERVER instead of "
                    "HOST/server.domain.local). The KDC validates the SPN against "
                    "the target's servicePrincipalName attribute."
                )
    elif fqdn_spns and short_spns:
        for path in finding.attack_paths:
            if path.commands_key:
                path.notes.append(
                    "SPN hostname mismatch: mixed FQDN and short hostnames in "
                    "allowed SPNs. If S4U2Proxy fails for one format, try the "
                    "other. The KDC matches the requested SPN against the target's "
                    "servicePrincipalName attribute."
                )
