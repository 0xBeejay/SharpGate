"""LDAP connection management for SharpGate."""

from __future__ import annotations

import ssl
from dataclasses import dataclass

import ldap3
from ldap3 import NTLM, SASL, SIMPLE, Connection, Server, Tls


@dataclass
class AuthConfig:
    """Authentication configuration."""
    domain: str
    username: str
    dc_ip: str
    password: str | None = None
    nthash: str | None = None
    use_kerberos: bool = False
    use_ldaps: bool = False

    @property
    def bind_user(self) -> str:
        """Format user for LDAP bind: DOMAIN\\user."""
        if "\\" in self.username or "@" in self.username:
            return self.username
        short_domain = self.domain.split(".")[0].upper()
        return f"{short_domain}\\{self.username}"

    @property
    def domain_dn(self) -> str:
        """Convert domain to base DN: corp.local -> DC=corp,DC=local."""
        return ",".join(f"DC={p}" for p in self.domain.split("."))


class LDAPConnection:
    """Manages LDAP connections to domain controllers."""

    def __init__(self, auth: AuthConfig):
        self.auth = auth
        self.conn: Connection | None = None

    def connect(self) -> Connection:
        """Establish LDAP connection with configured auth method."""
        port = 636 if self.auth.use_ldaps else 389
        use_ssl = self.auth.use_ldaps

        tls_config = None
        if use_ssl:
            tls_config = Tls(validate=ssl.CERT_NONE)

        server = Server(
            self.auth.dc_ip,
            port=port,
            use_ssl=use_ssl,
            tls=tls_config,
            get_info=ldap3.ALL,
        )

        if self.auth.use_kerberos:
            self.conn = Connection(
                server,
                authentication=SASL,
                sasl_mechanism="GSSAPI",
                auto_bind=True,
            )
        elif self.auth.nthash:
            ntlm_pass = f"aad3b435b51404eeaad3b435b51404ee:{self.auth.nthash}"
            self.conn = Connection(
                server,
                user=self.auth.bind_user,
                password=ntlm_pass,
                authentication=NTLM,
                auto_bind=True,
            )
        else:
            self.conn = Connection(
                server,
                user=self.auth.bind_user,
                password=self.auth.password,
                authentication=NTLM,
                auto_bind=True,
            )

        return self.conn

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str] | str = ldap3.ALL_ATTRIBUTES,
        search_scope: str = ldap3.SUBTREE,
    ) -> list:
        """Perform an LDAP search and return entries."""
        if not self.conn:
            raise RuntimeError("Not connected. Call connect() first.")

        self.conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=search_scope,
            attributes=attributes,
        )
        return self.conn.entries

    def get_domain_sid(self) -> str:
        """Retrieve the domain SID from the domain object."""
        entries = self.search(
            search_base=self.auth.domain_dn,
            search_filter="(objectClass=domain)",
            attributes=["objectSid"],
            search_scope=ldap3.BASE,
        )
        if entries:
            return str(entries[0]["objectSid"])
        return ""

    def close(self):
        """Close the LDAP connection."""
        if self.conn:
            self.conn.unbind()
            self.conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()
