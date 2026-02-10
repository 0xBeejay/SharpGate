"""Enumerate accounts protected from delegation abuse."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sharpgate.analyser.models import ProtectedAccount, UACFlag

if TYPE_CHECKING:
    from sharpgate.connection import LDAPConnection


def enumerate_protected_users(conn: LDAPConnection) -> list[ProtectedAccount]:
    """Find members of the Protected Users group.

    Members of this group are protected from credential delegation,
    NTLM authentication, and unconstrained delegation abuse.

    Returns:
        List of ProtectedAccount objects
    """
    # Find the Protected Users group and get its members
    search_filter = "(&(objectClass=group)(cn=Protected Users))"
    attributes = ["member"]

    try:
        entries = conn.search(
            search_base=conn.auth.domain_dn,
            search_filter=search_filter,
            attributes=attributes,
        )
    except Exception:
        return []

    if not entries:
        return []

    members = _get_list(entries[0], "member")
    protected: list[ProtectedAccount] = []

    for member_dn in members:
        try:
            member_entries = conn.search(
                search_base=member_dn,
                search_filter="(objectClass=*)",
                attributes=["sAMAccountName", "adminCount"],
                search_scope="BASE",
            )
            if member_entries:
                sam = _get_str(member_entries[0], "sAMAccountName")
                admin_count = _get_int(member_entries[0], "adminCount")
                protected.append(ProtectedAccount(
                    samaccountname=sam,
                    dn=member_dn,
                    protection_type="Protected Users",
                    is_admin=admin_count > 0,
                ))
        except Exception:
            continue

    return protected


def enumerate_not_delegated(conn: LDAPConnection) -> list[ProtectedAccount]:
    """Find accounts with the NOT_DELEGATED (Account is sensitive) UAC flag.

    These accounts' TGTs cannot be forwarded via delegation, blocking
    unconstrained and constrained delegation attacks against them.

    Returns:
        List of ProtectedAccount objects
    """
    # UAC bit for NOT_DELEGATED = 0x100000
    search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=1048576)"
    attributes = [
        "sAMAccountName",
        "distinguishedName",
        "adminCount",
    ]

    try:
        entries = conn.search(
            search_base=conn.auth.domain_dn,
            search_filter=search_filter,
            attributes=attributes,
        )
    except Exception:
        return []

    protected: list[ProtectedAccount] = []

    for entry in entries:
        sam = _get_str(entry, "sAMAccountName")
        dn = _get_str(entry, "distinguishedName")
        admin_count = _get_int(entry, "adminCount")

        protected.append(ProtectedAccount(
            samaccountname=sam,
            dn=dn,
            protection_type="NOT_DELEGATED",
            is_admin=admin_count > 0,
        ))

    return protected


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
