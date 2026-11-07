"""
FortiSASE VPN session inventory, independent of shared PoP bandwidth.
"""
from cmk.agent_based.v2 import AgentSection, CheckPlugin, CheckResult, DiscoveryResult
from ..lib.common import SessionSection, check_sessions, discover_sessions, parse_sessions


def discover_vpn(section: SessionSection) -> DiscoveryResult:
    """
    Discover the regions returned by the VPN session API.

    Input:
        section: Validated protocol-specific regional inventory.

    Output:
        One session service per region, including valid empty session lists.

    """
    yield from discover_sessions(section)


def check_vpn(item: str, section: SessionSection) -> CheckResult:
    """
    Evaluate session count and session byte totals for VPN.

    Input:
        item: Region identifier accepted during discovery.
        section: Session records normalized for this protocol.

    Output:
        Session measurements and validation diagnostics; bandwidth belongs to the PoP service.

    """
    yield from check_sessions(item, section)


agent_section_vpn_sessions = AgentSection(name='fortisase_vpn_sessions', parse_function=parse_sessions)
check_plugin_vpn_sessions = CheckPlugin(
    name='fortisase_vpn_sessions', service_name='FortiSASE VPN %s',
    sections=['fortisase_vpn_sessions'], discovery_function=discover_vpn, check_function=check_vpn)
