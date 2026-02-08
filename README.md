# SharpGate

AD delegation abuse mapper and attack path analysis tool. Enumerates Kerberos delegation configurations via LDAP (unconstrained, constrained, RBCD), classifies them, identifies exploitable attack paths, and generates copy-paste commands for common offensive tooling.

Built for pentesters and red teamers working in Active Directory environments with delegation misconfigurations.

## Features

- **Delegation Enumeration** — Queries unconstrained (`TRUSTED_FOR_DELEGATION`), constrained (`msDS-AllowedToDelegateTo`), and RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`) configurations
- **Type Classification** — Identifies delegation type, detects protocol transition (T2A4D), and flags domain controllers
- **SPN Analysis** — Parses allowed SPNs, maps alternative service names (HTTP -> WSMAN/CIFS/LDAP), and detects DC-targeting delegation
- **Attack Path Engine** — Maps viable attacks per delegation type with severity ratings (TGT capture, S4U chains, RBCD setup, DC coercion)
- **Command Generation** — Produces step-by-step commands with prerequisites and notes for both Linux and Windows toolsets
- **Protected Account Enumeration** — Identifies Protected Users members and accounts with `NOT_DELEGATED` flag
- **Rich Output** — Coloured tables, ASCII delegation chain map, severity-rated attack paths, and copy-paste command panels

## Supported Toolsets

| Linux | Windows |
|-------|---------|
| Impacket (getST, addcomputer, rbcd, secretsdump) | Rubeus |
| krbrelayx | Mimikatz |
| PetitPotam / printerbug | SpoolSample |
| dnstool | PowerView / StandIn |

## Installation

```bash
git clone https://github.com/0xBeejay/SharpGate.git
cd SharpGate
pip install .
```

### Requirements

- Python 3.9+
- `ldap3`, `impacket`, `rich`, `click`

## Usage

```bash
# Password authentication
sharpgate -d corp.local -u admin -p 'Password1' --dc 10.10.1.1

# NTLM hash authentication
sharpgate -d corp.local -u admin -H aad3b435:ntlmhash --dc 10.10.1.1

# Kerberos authentication (uses KRB5CCNAME)
sharpgate -d corp.local -k --dc 10.10.1.1

# Linux commands only
sharpgate -d corp.local -u admin -p pass --dc 10.10.1.1 --toolset linux

# Windows commands only
sharpgate -d corp.local -u admin -p pass --dc 10.10.1.1 --toolset windows

# Filter by delegation type
sharpgate -d corp.local -u admin -p pass --dc 10.10.1.1 --type unconstrained

# Focus on a specific account
sharpgate -d corp.local -u admin -p pass --dc 10.10.1.1 --account SQLSERVER$

# Include domain controllers (excluded by default)
sharpgate -d corp.local -u admin -p pass --dc 10.10.1.1 --include-dcs

# Skip RBCD or protected account enumeration
sharpgate -d corp.local -u admin -p pass --dc 10.10.1.1 --no-rbcd --no-protected
```

## Options

```
-d, --domain        Target domain (e.g. corp.local)                        [required]
-u, --username      Username for authentication
-p, --password      Password for authentication
-H, --hashes        NTLM hash (LM:NT or :NT format)
-k, --kerberos      Use Kerberos auth (KRB5CCNAME)
--dc                Domain controller IP address                            [required]
--ldaps             Use LDAPS (port 636)
--toolset           Command toolset: linux, windows, or all                 [default: all]
--type              Filter: unconstrained, constrained, rbcd, or all        [default: all]
--account           Focus on a specific account
--include-dcs       Include domain controllers in unconstrained results
--no-rbcd           Skip RBCD enumeration
--no-protected      Skip protected account enumeration
```

## Output

SharpGate produces:

1. **Delegation Map** — ASCII diagram showing all delegation relationships grouped by type with severity tags
2. **Summary Table** — Overview of all findings with delegation type, target SPNs/principals, and attack path counts
3. **Protected Accounts Panel** — Members of Protected Users and accounts with `NOT_DELEGATED` flag
4. **Finding Detail Panels** — Per-account breakdown of delegation configuration, UAC flags, and allowed services
5. **Attack Paths** — Severity-rated (CRITICAL/HIGH/MEDIUM) attack vectors with descriptions and prerequisites
6. **Command Blocks** — Step-by-step commands grouped by tool, with prereqs and cleanup steps

## Delegation Types

| Type | LDAP Indicator | Key Attribute |
|------|---------------|---------------|
| Unconstrained | `userAccountControl` & `0x80000` | TRUSTED_FOR_DELEGATION flag |
| Constrained | `msDS-AllowedToDelegateTo` present | SPN list |
| Constrained + T2A4D | Above + UAC & `0x1000000` | TRUSTED_TO_AUTH_FOR_DELEGATION flag |
| RBCD | `msDS-AllowedToActOnBehalfOfOtherIdentity` present | Security descriptor (binary) |

## Attack Paths Detected

| Attack | Applies To | Severity |
|--------|-----------|----------|
| TGT Capture via DC Coercion | Unconstrained (non-DC) | CRITICAL |
| S4U2Self + S4U2Proxy (any user, no interaction) | Constrained + T2A4D | CRITICAL |
| S4U + Alt Service Name -> DCSync | Constrained + T2A4D targeting DC | CRITICAL |
| S4U2Proxy (requires client TGT) | Constrained (no T2A4D) | HIGH |
| S4U + Alt Service Name -> DC | Constrained (no T2A4D) targeting DC | HIGH |
| RBCD S4U from allowed principal | RBCD (existing config) | HIGH |
| RBCD Setup (add machine + write attribute) | RBCD (write access to target) | MEDIUM |
| High-Value Delegation Account | Any (adminCount=1) | MEDIUM |
| Unconstrained DC (expected config) | Unconstrained (DC) | INFO |

## Alternative Service Name Trick

When constrained delegation allows access to one SPN on a host, the ticket is encrypted with the host's key — not the SPN's. This means the service type can be rewritten to access other services on the same machine:

| Original SPN | Also Accessible |
|-------------|----------------|
| HTTP/server | WSMAN, TERMSRV, RPCSS |
| CIFS/server | SMB |
| LDAP/server | GC |
| HOST/server | NETLOGON, DNS, SCHEDULE, and 40+ others |

SharpGate detects these automatically and generates the appropriate `-altservice` flags for getST.py and Rubeus.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Only use against environments you have explicit permission to test.
