"""
FortiSASE SWG session inventory, independent of shared PoP bandwidth.
"""
from cmk.agent_based.v2 import AgentSection, CheckPlugin, CheckResult, DiscoveryResult
from ..lib.common import SessionSection, check_sessions, discover_sessions, parse_sessions


def discover_swg(section: SessionSection) -> DiscoveryResult:
    """
    Discover the regions returned by the SWG session API.

    Input:
        section: Validated protocol-specific regional inventory.

    Output:
        One session service per region, including valid empty session lists.

    """
    yield from discover_sessions(section)


def check_swg(item: str, section: SessionSection) -> CheckResult:
    """
    Evaluate session count and session byte totals for SWG.

    Input:
        item: Region identifier accepted during discovery.
        section: Session records normalized for this protocol.

    Output:
        Session measurements and validation diagnostics; bandwidth belongs to the PoP service.

    """
    yield from check_sessions(item, section)


agent_section_swg_sessions = AgentSection(name='fortisase_swg_sessions', parse_function=parse_sessions)
check_plugin_swg_sessions = CheckPlugin(
    name='fortisase_swg_sessions', service_name='FortiSASE SWG %s',
    sections=['fortisase_swg_sessions'], discovery_function=discover_swg, check_function=check_swg)
