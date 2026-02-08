"""Enumerate accounts with unconstrained delegation (TRUSTED_FOR_DELEGATION)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sharpgate.analyser.models import AccountType, DelegationFinding, UACFlag

if TYPE_CHECKING:
    from sharpgate.connection import LDAPConnection

# UAC flag for unconstrained delegation
_TRUSTED_FOR_DELEGATION = 0x80000


def enumerate_unconstrained(
    conn: LDAPConnection,
    include_dcs: bool = False,
) -> list[DelegationFinding]:
    """Find all accounts with unconstrained delegation configured.

    Args:
        conn: Active LDAP connection
        include_dcs: If True, include domain controllers (they have this flag by default)

    Returns:
        List of DelegationFinding objects for unconstrained delegation accounts
    """
    search_filter = (
        "(&"
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(!(objectClass=msDS-GroupManagedServiceAccount))"
        ")"
    )

    attributes = [
        "sAMAccountName",
        "distinguishedName",
        "userAccountControl",
        "objectClass",
        "adminCount",
        "servicePrincipalName",
    ]

    try:
        entries = conn.search(
            search_base=conn.auth.domain_dn,
            search_filter=search_filter,
            attributes=attributes,
        )
    except Exception:
        return []

    findings: list[DelegationFinding] = []

    for entry in entries:
        sam = _get_str(entry, "sAMAccountName")
        dn = _get_str(entry, "distinguishedName")
        uac = _get_int(entry, "userAccountControl")
        object_classes = _get_list(entry, "objectClass")
        admin_count = _get_int(entry, "adminCount")

        account_type = _classify_account(object_classes)
        is_dc = bool(uac & UACFlag.SERVER_TRUST)

        if is_dc and not include_dcs:
            continue

        finding = DelegationFinding(
            samaccountname=sam,
            dn=dn,
            domain=conn.auth.domain,
            uac=uac,
            account_type=account_type,
            is_dc=is_dc,
            is_enabled=not bool(uac & UACFlag.ACCOUNTDISABLE),
            admin_count=admin_count,
        )

        findings.append(finding)

    return findings


def _classify_account(object_classes: list[str]) -> AccountType:
    """Determine account type from objectClass values."""
    classes_lower = [c.lower() for c in object_classes]
    if "computer" in classes_lower:
        return AccountType.COMPUTER
    if "msds-managedserviceaccount" in classes_lower or "msds-groupmanagedserviceaccount" in classes_lower:
        return AccountType.MANAGED_SERVICE
    if "user" in classes_lower:
        return AccountType.USER
    return AccountType.UNKNOWN


def _get_str(entry, attr: str) -> str:
    """Safely extract a string attribute from an LDAP entry."""
    try:
        val = entry[attr]
        return str(val) if val else ""
    except (KeyError, IndexError):
        return ""


def _get_int(entry, attr: str) -> int:
    """Safely extract an integer attribute from an LDAP entry."""
    try:
        val = entry[attr]
        return int(val) if val else 0
    except (KeyError, IndexError, ValueError):
        return 0


def _get_list(entry, attr: str) -> list[str]:
    """Safely extract a list attribute from an LDAP entry."""
    try:
        val = entry[attr]
        if hasattr(val, "values"):
            return list(val.values)
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)] if val else []
    except (KeyError, IndexError):
        return []
