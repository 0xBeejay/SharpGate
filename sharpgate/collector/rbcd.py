"""Enumerate accounts with Resource-Based Constrained Delegation (RBCD)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sharpgate.analyser.models import (
    AccountType,
    DelegationFinding,
    RBCDPrincipal,
    UACFlag,
)

if TYPE_CHECKING:
    from sharpgate.connection import LDAPConnection


def enumerate_rbcd(conn: LDAPConnection) -> list[DelegationFinding]:
    """Find all accounts with msDS-AllowedToActOnBehalfOfOtherIdentity set.

    Parses the security descriptor blob to extract the SIDs of accounts
    that are allowed to delegate to each target.

    Returns:
        List of DelegationFinding objects for RBCD targets
    """
    search_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"

    attributes = [
        "sAMAccountName",
        "distinguishedName",
        "userAccountControl",
        "objectClass",
        "adminCount",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
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

        # Parse the security descriptor to extract allowed SIDs
        sd_bytes = _get_bytes(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        rbcd_principals = _parse_sd_principals(sd_bytes)

        # Resolve SIDs to sAMAccountNames
        _resolve_principals(conn, rbcd_principals)

        account_type = _classify_account(object_classes)
        is_dc = bool(uac & UACFlag.SERVER_TRUST)

        finding = DelegationFinding(
            samaccountname=sam,
            dn=dn,
            domain=conn.auth.domain,
            uac=uac,
            account_type=account_type,
            is_dc=is_dc,
            is_enabled=not bool(uac & UACFlag.ACCOUNTDISABLE),
            admin_count=admin_count,
            rbcd_principals=rbcd_principals,
        )

        findings.append(finding)

    return findings


def _parse_sd_principals(sd_bytes: bytes) -> list[RBCDPrincipal]:
    """Parse a security descriptor blob to extract allowed SIDs.

    Uses impacket's ldaptypes to parse the DACL and extract
    ACCESS_ALLOWED_ACE entries.
    """
    if not sd_bytes:
        return []

    try:
        from impacket.ldap import ldaptypes

        ldaptypes.TypesMixin.RECALC = False
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(sd_bytes)

        principals: list[RBCDPrincipal] = []

        if sd["Dacl"] is not None:
            for ace in sd["Dacl"].aces:
                sid = ace["Ace"]["Sid"].formatCanonical()
                principals.append(RBCDPrincipal(sid=sid))

        return principals

    except Exception:
        return []


def _resolve_principals(conn: LDAPConnection, principals: list[RBCDPrincipal]):
    """Resolve SIDs to sAMAccountNames via LDAP lookups."""
    for principal in principals:
        try:
            entries = conn.search(
                search_base=conn.auth.domain_dn,
                search_filter=f"(objectSid={principal.sid})",
                attributes=["sAMAccountName", "distinguishedName"],
            )
            if entries:
                principal.samaccountname = _get_str(entries[0], "sAMAccountName")
                principal.dn = _get_str(entries[0], "distinguishedName")
        except Exception:
            continue


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


def _get_bytes(entry, attr: str) -> bytes:
    """Safely extract raw bytes from an LDAP entry."""
    try:
        val = entry[attr]
        if hasattr(val, "raw_values") and val.raw_values:
            return val.raw_values[0]
        if isinstance(val, bytes):
            return val
        return b""
    except (KeyError, IndexError, TypeError):
        return b""
