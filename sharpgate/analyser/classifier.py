"""Classify delegation findings by type, detect DCs, and enrich SPNs."""

from __future__ import annotations

from sharpgate.analyser.models import DelegationFinding, DelegationType


def classify(finding: DelegationFinding) -> DelegationFinding:
    """Classify a single delegation finding.

    Determines the delegation type based on LDAP attributes:
    - Unconstrained: TRUSTED_FOR_DELEGATION UAC flag
    - Constrained + T2A4D: msDS-AllowedToDelegateTo + TRUSTED_TO_AUTH_FOR_DELEGATION
    - Constrained: msDS-AllowedToDelegateTo only
    - RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity (rbcd_principals populated)

    Returns:
        The finding with delegation_type set
    """
    if finding.rbcd_principals:
        finding.delegation_type = DelegationType.RBCD
    elif finding.is_unconstrained:
        finding.delegation_type = DelegationType.UNCONSTRAINED
    elif finding.is_constrained and finding.is_t2a4d:
        finding.delegation_type = DelegationType.CONSTRAINED_T2A4D
    elif finding.is_constrained:
        finding.delegation_type = DelegationType.CONSTRAINED

    return finding


def classify_all(findings: list[DelegationFinding]) -> list[DelegationFinding]:
    """Classify all delegation findings."""
    for finding in findings:
        classify(finding)
    return findings


def detect_dc_targets(
    findings: list[DelegationFinding],
    dc_names: list[str],
) -> None:
    """Mark constrained delegation SPNs that target domain controllers.

    Args:
        findings: Classified delegation findings
        dc_names: List of known DC hostnames/sAMAccountNames (lowercase)
    """
    dc_set = {n.lower().rstrip("$") for n in dc_names}

    for finding in findings:
        if finding.delegation_type not in (
            DelegationType.CONSTRAINED,
            DelegationType.CONSTRAINED_T2A4D,
        ):
            continue

        for svc in finding.allowed_services:
            host = svc.target_host
            # Strip domain suffix for comparison
            short = host.split(".")[0].lower()
            if short in dc_set or host in dc_set:
                svc._targets_dc = True  # type: ignore[attr-defined]


def get_dc_hostnames(findings: list[DelegationFinding]) -> list[str]:
    """Extract DC hostnames from findings (accounts with SERVER_TRUST UAC flag)."""
    dcs: list[str] = []
    for finding in findings:
        if finding.is_dc:
            dcs.append(finding.samaccountname.lower().rstrip("$"))
    return dcs
