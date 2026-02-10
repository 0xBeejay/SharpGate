"""Enumerate accounts with constrained delegation (msDS-AllowedToDelegateTo)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sharpgate.analyser.models import (
    AccountType,
    AllowedService,
    DelegationFinding,
    UACFlag,
)

if TYPE_CHECKING:
    from sharpgate.connection import LDAPConnection


def enumerate_constrained(conn: LDAPConnection) -> list[DelegationFinding]:
    """Find all accounts with constrained delegation configured.

    Queries for accounts that have msDS-AllowedToDelegateTo set,
    and checks whether TRUSTED_TO_AUTH_FOR_DELEGATION (T2A4D / protocol
    transition) is also enabled.

    Returns:
        List of DelegationFinding objects for constrained delegation accounts
    """
    search_filter = "(msDS-AllowedToDelegateTo=*)"

    attributes = [
        "sAMAccountName",
        "distinguishedName",
        "userAccountControl",
        "objectClass",
        "adminCount",
        "msDS-AllowedToDelegateTo",
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
        allowed_spns = _get_list(entry, "msDS-AllowedToDelegateTo")

        account_type = _classify_account(object_classes)
        is_dc = bool(uac & UACFlag.SERVER_TRUST)
        has_t2a4d = bool(uac & UACFlag.TRUSTED_TO_AUTH_FOR_DELEGATION)

        allowed_services = [AllowedService(raw_spn=spn) for spn in allowed_spns]

        finding = DelegationFinding(
            samaccountname=sam,
            dn=dn,
            domain=conn.auth.domain,
            uac=uac,
            account_type=account_type,
            is_dc=is_dc,
            is_enabled=not bool(uac & UACFlag.ACCOUNTDISABLE),
            admin_count=admin_count,
            allowed_services=allowed_services,
            has_protocol_transition=has_t2a4d,
        )

        findings.append(finding)

    return findings


def _classify_account(object_classes: list[str]) -> AccountType:
    classes_lower = [c.lower() for c in object_classes]
    if "computer" in classes_lower:
        return AccountType.COMPUTER
    if "msds-managedserviceaccount" in classes_lower or "msds-groupmanagedserviceaccount" in classes_lower:
        return AccountType.MANAGED_SERVICE
    if "user" in classes_lower:
        return AccountType.USER
    return AccountType.UNKNOWN


def _get_str(entry, attr: str) -> str:
    try:
        val = entry[attr]
        if hasattr(val, "value"):
            val = val.value
        return str(val) if val else ""
    except (KeyError, IndexError, TypeError):
        return ""


def _get_int(entry, attr: str) -> int:
    try:
        val = entry[attr]
        if hasattr(val, "value"):
            val = val.value
        return int(val) if val else 0
    except (KeyError, IndexError, ValueError, TypeError):
        return 0


def _get_list(entry, attr: str) -> list[str]:
    try:
        val = entry[attr]
        if hasattr(val, "values"):
            return [str(v) for v in val.values]
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)] if val else []
    except (KeyError, IndexError, TypeError):
        return []
