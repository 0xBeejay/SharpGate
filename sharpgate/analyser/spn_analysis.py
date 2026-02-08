"""SPN analysis: alternative service name trick and DC target mapping."""

from __future__ import annotations

from sharpgate.analyser.models import AllowedService, DelegationFinding, DelegationType

# Alternative service names that share the same service ticket.
# If you have a ticket for one, you can rewrite it to any other in the same group.
# See: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)
ALTERNATIVE_SERVICES: dict[str, list[str]] = {
    "HTTP": ["HTTP", "WSMAN", "TERMSRV", "RPCSS"],
    "WSMAN": ["HTTP", "WSMAN", "TERMSRV", "RPCSS"],
    "CIFS": ["CIFS", "SMB"],
    "HOST": ["HOST", "ALERTER", "APPMGMT", "CISVC", "CLIPSRV", "BROWSER",
             "DHCP", "DNSCACHE", "REPLICATOR", "EVENTLOG", "EVENTSYSTEM",
             "POLICYAGENT", "OAKLEY", "DMSERVER", "DNS", "MCSVC", "FAX",
             "MSISERVER", "IPSEC", "IAS", "MESSENGER", "NETLOGON",
             "NETMAN", "NETDDE", "NETDDEDSM", "NMAGENT", "PLUGPLAY",
             "PROTECTEDSTORAGE", "RASMAN", "RPCLOCATOR", "RPC", "RPCSS",
             "REMOTEACCESS", "RSH", "SACSVR", "SCESRV", "SCHEDULE",
             "SCMNOTIFY", "SECLOGON", "SMTPSVC", "SNMP", "SPOOLER",
             "TAPISRV", "TRKSVR", "TRKWKS", "TIMESVC", "WINS", "W3SVC",
             "IISADMIN", "SMTP"],
    "LDAP": ["LDAP", "GC"],
    "MSSQLSVC": ["MSSQLSvc"],
    "TERMSRV": ["HTTP", "WSMAN", "TERMSRV", "RPCSS"],
}

# Services that enable high-impact abuse when targeting DCs
DC_CRITICAL_SERVICES = {"LDAP", "GC", "CIFS", "HTTP", "HOST", "WSMAN", "RPCSS"}


def get_alternative_services(service_type: str) -> list[str]:
    """Return the list of alternative service names for a given SPN service type.

    The alternative service name trick allows rewriting the service portion
    of a Kerberos ticket to access different services on the same host,
    because the service ticket is encrypted with the target host's key.
    """
    return ALTERNATIVE_SERVICES.get(service_type.upper(), [service_type.upper()])


def analyse_spn_targets(finding: DelegationFinding, dc_hostnames: list[str]) -> dict:
    """Analyse the SPN targets for a constrained delegation finding.

    Returns a dict with:
        - targets_dc: bool - whether any SPN targets a DC
        - dc_services: list of AllowedService that target DCs
        - alternative_services: dict mapping hostname -> list of reachable service types
        - critical_access: list of (hostname, service) tuples with high-impact access
    """
    if finding.delegation_type not in (
        DelegationType.CONSTRAINED,
        DelegationType.CONSTRAINED_T2A4D,
    ):
        return {}

    dc_set = {h.lower().rstrip("$") for h in dc_hostnames}

    result = {
        "targets_dc": False,
        "dc_services": [],
        "alternative_services": {},
        "critical_access": [],
    }

    for svc in finding.allowed_services:
        host = svc.target_host
        short_host = host.split(".")[0].lower()
        is_dc = short_host in dc_set or host in dc_set

        # Map alternative services for this host
        alt_services = get_alternative_services(svc.service_type)
        if host not in result["alternative_services"]:
            result["alternative_services"][host] = set()
        result["alternative_services"][host].update(alt_services)

        if is_dc:
            result["targets_dc"] = True
            result["dc_services"].append(svc)

            # Check for critical service access via alternatives
            reachable = set(alt_services)
            for critical in DC_CRITICAL_SERVICES:
                if critical in reachable:
                    result["critical_access"].append((host, critical))

    # Convert sets to sorted lists for consistent output
    for host in result["alternative_services"]:
        result["alternative_services"][host] = sorted(result["alternative_services"][host])

    return result
