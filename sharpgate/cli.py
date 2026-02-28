"""Click CLI, auth handling, and argument parsing for SharpGate."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from sharpgate.analyser.classifier import classify_all, detect_dc_targets, get_dc_hostnames
from sharpgate.analyser.paths import analyse_all_paths
from sharpgate.collector.constrained import enumerate_constrained
from sharpgate.collector.rbcd import enumerate_rbcd
from sharpgate.collector.sensitive_accounts import (
    enumerate_not_delegated,
    enumerate_protected_users,
)
from sharpgate.collector.unconstrained import enumerate_unconstrained
from sharpgate.connection import AuthConfig, LDAPConnection
from sharpgate.output.console import SharpGateOutput


@click.command()
@click.option("-d", "--domain", required=True, help="Target domain (e.g. corp.local)")
@click.option("-u", "--username", default=None, help="Username for authentication")
@click.option("-p", "--password", default=None, help="Password for authentication")
@click.option("-H", "--hashes", default=None, help="NTLM hash (LM:NT or :NT format)")
@click.option("-k", "--kerberos", is_flag=True, help="Use Kerberos auth (KRB5CCNAME)")
@click.option("--dc", required=True, help="Domain controller IP address")
@click.option("--ldaps", is_flag=True, help="Use LDAPS (port 636)")
@click.option(
    "--toolset",
    type=click.Choice(["linux", "windows", "all"]),
    default="all",
    help="Command toolset to generate (default: all)",
)
@click.option(
    "--type",
    "deleg_type",
    type=click.Choice(["unconstrained", "constrained", "rbcd", "all"]),
    default="all",
    help="Filter by delegation type (default: all)",
)
@click.option("--account", default=None, help="Focus on a specific account")
@click.option("--include-dcs", is_flag=True, help="Include domain controllers in results")
@click.option("--no-rbcd", is_flag=True, help="Skip RBCD enumeration")
@click.option("--no-protected", is_flag=True, help="Skip protected account enumeration")
@click.option("--brief", is_flag=True, help="Compact output: summary table only, no full commands")
def main(
    domain: str,
    username: str | None,
    password: str | None,
    hashes: str | None,
    kerberos: bool,
    dc: str,
    ldaps: bool,
    toolset: str,
    deleg_type: str,
    account: str | None,
    include_dcs: bool,
    no_rbcd: bool,
    no_protected: bool,
    brief: bool,
):
    """SharpGate - AD delegation abuse mapper and attack path analysis.

    Enumerates Active Directory delegation configurations (unconstrained,
    constrained, RBCD), classifies them, identifies exploitable paths,
    and generates attack commands.
    """
    console = Console()
    output = SharpGateOutput(console)
    output.print_banner(domain)

    # Validate auth options
    if not kerberos and not username:
        output.print_error("Must provide -u/--username or -k/--kerberos")
        sys.exit(1)

    if not kerberos and not password and not hashes:
        output.print_error("Must provide -p/--password, -H/--hashes, or -k/--kerberos")
        sys.exit(1)

    # Parse hash
    nthash = None
    if hashes:
        if ":" in hashes:
            nthash = hashes.split(":")[-1]
        else:
            nthash = hashes

    auth = AuthConfig(
        domain=domain,
        username=username or "",
        dc_ip=dc,
        password=password,
        nthash=nthash,
        use_kerberos=kerberos,
        use_ldaps=ldaps,
    )

    # Connect
    ldap_conn = LDAPConnection(auth)

    try:
        output.print_info(f"Connecting to {dc} ({domain})...")
        ldap_conn.connect()
        output.print_info("Connected successfully.")
    except Exception as e:
        output.print_error(f"Failed to connect: {e}")
        sys.exit(1)

    try:
        # Phase 1: Collect delegation configurations
        output.print_section("Collecting Delegation Configurations")
        all_findings = []

        # Unconstrained delegation
        if deleg_type in ("unconstrained", "all"):
            output.print_info("Enumerating unconstrained delegation...")
            unconstrained = enumerate_unconstrained(ldap_conn, include_dcs=include_dcs)
            output.print_collector_status("Unconstrained delegation", len(unconstrained))
            all_findings.extend(unconstrained)

        # Constrained delegation
        if deleg_type in ("constrained", "all"):
            output.print_info("Enumerating constrained delegation...")
            constrained = enumerate_constrained(ldap_conn)
            output.print_collector_status("Constrained delegation", len(constrained))
            all_findings.extend(constrained)

        # RBCD
        if deleg_type in ("rbcd", "all") and not no_rbcd:
            output.print_info("Enumerating RBCD configurations...")
            rbcd = enumerate_rbcd(ldap_conn)
            output.print_collector_status("RBCD configurations", len(rbcd))
            all_findings.extend(rbcd)

        if not all_findings:
            output.print_no_findings(domain)
            return

        # Phase 2: Classify findings
        output.print_info("Classifying delegation types...")
        classify_all(all_findings)

        # Detect DC hostnames for SPN analysis
        dc_hostnames = get_dc_hostnames(all_findings)
        # Also include DCs found via unconstrained (if --include-dcs was used)
        if include_dcs:
            detect_dc_targets(all_findings, dc_hostnames)

        # Phase 3: Analyse attack paths
        output.print_info("Analysing attack paths...")
        analyse_all_paths(all_findings, dc_hostnames=dc_hostnames)

        # Phase 4: Collect protected accounts
        protected_users = []
        not_delegated = []
        if not no_protected:
            output.print_info("Enumerating protected accounts...")
            protected_users = enumerate_protected_users(ldap_conn)
            not_delegated = enumerate_not_delegated(ldap_conn)
            output.print_collector_status("Protected Users members", len(protected_users))
            output.print_collector_status("NOT_DELEGATED accounts", len(not_delegated))

        # Phase 5: Output results
        output.print_results(
            domain=domain,
            findings=all_findings,
            protected_users=protected_users,
            not_delegated=not_delegated,
            toolset=toolset,
            focus_account=account,
            focus_type=deleg_type if deleg_type != "all" else None,
            brief=brief,
        )

    except Exception as e:
        output.print_error(f"Enumeration failed: {e}")
        raise
    finally:
        ldap_conn.close()


if __name__ == "__main__":
    main()
