"""Delegation dataclass models and enums for SharpGate."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class DelegationType(enum.Enum):
    """Type of Kerberos delegation configured on an account."""
    UNCONSTRAINED = "Unconstrained"
    CONSTRAINED = "Constrained"
    CONSTRAINED_T2A4D = "Constrained + Protocol Transition"
    RBCD = "Resource-Based Constrained"

    @property
    def short(self) -> str:
        return {
            "Unconstrained": "UNCONSTRAINED",
            "Constrained": "CONSTRAINED",
            "Constrained + Protocol Transition": "CONSTRAINED+T2A4D",
            "Resource-Based Constrained": "RBCD",
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "Unconstrained": "red",
            "Constrained": "yellow",
            "Constrained + Protocol Transition": "red",
            "Resource-Based Constrained": "blue",
        }[self.value]


class AccountType(enum.Enum):
    """Type of AD account with delegation configured."""
    COMPUTER = "Computer"
    USER = "User"
    MANAGED_SERVICE = "Managed Service Account"
    UNKNOWN = "Unknown"


class Severity(enum.Enum):
    """Attack path severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "blue",
            "LOW": "dim",
            "INFO": "dim",
        }[self.value]


class UACFlag(enum.IntFlag):
    """UserAccountControl flags relevant to delegation."""
    ACCOUNTDISABLE = 0x2
    WORKSTATION_TRUST = 0x1000
    SERVER_TRUST = 0x2000          # Domain controller
    DONT_EXPIRE_PASSWORD = 0x10000
    TRUSTED_FOR_DELEGATION = 0x80000  # Unconstrained delegation
    NOT_DELEGATED = 0x100000       # Account is sensitive, cannot be delegated
    USE_DES_KEY_ONLY = 0x200000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # Protocol transition (T2A4D)


@dataclass
class AttackPath:
    """A single identified attack path for a delegation finding."""
    name: str
    severity: Severity
    description: str
    prerequisites: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    commands_key: str = ""


@dataclass
class AllowedService:
    """A single SPN from msDS-AllowedToDelegateTo, parsed into components."""
    raw_spn: str
    service_type: str = ""   # e.g. CIFS, HTTP, MSSQLSvc
    hostname: str = ""       # e.g. fileserver.corp.local
    port: str = ""           # e.g. 1433 (optional)

    def __post_init__(self):
        parts = self.raw_spn.split("/", 1)
        self.service_type = parts[0].upper() if parts else ""
        if len(parts) > 1:
            host_port = parts[1]
            if ":" in host_port:
                self.hostname, self.port = host_port.rsplit(":", 1)
            else:
                self.hostname = host_port

    @property
    def target_host(self) -> str:
        """Hostname without port."""
        return self.hostname.lower()

    @property
    def is_dc_service(self) -> bool:
        """Whether this SPN type is commonly found on DCs."""
        return self.service_type in ("LDAP", "GC", "DNS", "E3514235-4B06-11D1-AB04-00C04FC2DCD2")


@dataclass
class RBCDPrincipal:
    """An account allowed to delegate via RBCD (from the SD blob)."""
    sid: str
    samaccountname: str = ""
    dn: str = ""


@dataclass
class ProtectedAccount:
    """An account protected from delegation abuse."""
    samaccountname: str
    dn: str
    protection_type: str = ""  # "Protected Users" or "NOT_DELEGATED"
    is_admin: bool = False


@dataclass
class DelegationFinding:
    """Represents a single delegation configuration found on an account."""
    # Account identity
    samaccountname: str
    dn: str
    domain: str
    uac: int = 0

    # Account classification
    account_type: AccountType = AccountType.UNKNOWN
    is_dc: bool = False
    is_enabled: bool = True
    admin_count: int = 0

    # Delegation type (set by classifier)
    delegation_type: DelegationType | None = None

    # Unconstrained: just the flag
    # Constrained: allowed SPNs
    allowed_services: list[AllowedService] = field(default_factory=list)
    has_protocol_transition: bool = False  # T2A4D flag

    # RBCD: accounts allowed to delegate TO this target
    rbcd_principals: list[RBCDPrincipal] = field(default_factory=list)

    # Analysis results
    attack_paths: list[AttackPath] = field(default_factory=list)

    def has_uac_flag(self, flag: UACFlag) -> bool:
        return bool(self.uac & flag.value)

    @property
    def is_unconstrained(self) -> bool:
        return self.has_uac_flag(UACFlag.TRUSTED_FOR_DELEGATION)

    @property
    def is_constrained(self) -> bool:
        return len(self.allowed_services) > 0

    @property
    def is_t2a4d(self) -> bool:
        return self.has_uac_flag(UACFlag.TRUSTED_TO_AUTH_FOR_DELEGATION)

    @property
    def is_sensitive(self) -> bool:
        return self.has_uac_flag(UACFlag.NOT_DELEGATED)

    @property
    def spn_hostnames(self) -> list[str]:
        """Unique target hostnames from allowed services."""
        seen: set[str] = set()
        result: list[str] = []
        for svc in self.allowed_services:
            host = svc.target_host
            if host and host not in seen:
                seen.add(host)
                result.append(host)
        return result

    @property
    def spn_summary(self) -> str:
        """Comma-separated list of allowed SPNs."""
        return ", ".join(s.raw_spn for s in self.allowed_services)
