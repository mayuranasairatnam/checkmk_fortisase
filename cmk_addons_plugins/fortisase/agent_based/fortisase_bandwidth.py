"""
FortiSASE regional bandwidth services consuming normalized bit-per-second samples.
"""
from cmk.agent_based.v2 import (
    AgentSection, CheckPlugin, CheckResult, DiscoveryResult, Metric, Result, Service, State, render,
)

from ..lib.common import SessionSection, TrafficSection, bandwidth_locations, parse_traffic


def discover_bps(section: TrafficSection) -> DiscoveryResult:
    """
    Discover one throughput service per identified traffic region.

    Input:
        section: Validated regional traffic rates and parser diagnostics.

    Output:
        Yields services for regions with measurements or explicit sample errors.

    """
    for region in section.regions:
        yield Service(item=region)


def check_bps(item: str, section: TrafficSection) -> CheckResult:
    """
    Report available regional throughput and validation failures.

    Input:
        item: Region identifier from discovery.
        section: Normalized traffic section.

    Output:
        Yields finite throughput metrics and UNKNOWN results for invalid or absent samples.

    """
    region = section.regions.get(item)
    if region is None:
        yield Result(state=State.UNKNOWN, summary='Region not found in traffic data')
        return
    issues = (*section.errors, *region.errors)
    if issues:
        yield Result(state=State.UNKNOWN, summary='Invalid traffic data', details='\n'.join(issues))
    measurements = ((region.rx, 'Receive rate', 'fortisase_bps_rx'),
                    (region.tx, 'Transmit rate', 'fortisase_bps_tx'))
    if region.rx is None and region.tx is None:
        measurements = ((region.bps, 'Throughput', 'fortisase_bps'),)
    emitted = False
    for value, label, metric in measurements:
        if value is not None:
            emitted = True
            yield Result(state=State.OK, summary=f'{label}: {render.networkbandwidth(value / 8)}')
            yield Metric(metric, value)
    if not emitted and not issues:
        yield Result(state=State.UNKNOWN, summary='No throughput sample reported')


def _section(name: str) -> AgentSection:
    """
    Register the shared traffic normalizer for one agent section.

    Input:
        name: Established FortiSASE section identifier.

    Output:
        AgentSection producing a TrafficSection for all consuming checks.

    """
    return AgentSection(name=name, parse_function=parse_traffic)


def rate_registration(kind: str, label: str) -> tuple[AgentSection, CheckPlugin]:
    """
    Bind a traffic parser and its regional rate check in one declaration.

    Input:
        kind: Lowercase traffic-type suffix used in protocol identifiers.
        label: Traffic type displayed in service names.

    Output:
        Parser/check registration pair sharing the same rate section identifier.

    """
    name = f'fortisase_bps_{kind}'
    return _section(name), CheckPlugin(
        name=name, service_name=f'FortiSASE {label} Bandwidth %s',
        discovery_function=discover_bps, check_function=check_bps)


def discover_private_access(
    section_fortisase_bps_privateaccess: TrafficSection | None,
    section_fortisase_swg_sessions: SessionSection | None,
    section_fortisase_vpn_sessions: SessionSection | None,
) -> DiscoveryResult:
    """
    Discover private-access bandwidth using location and datacenter names.

    Input:
        section_fortisase_bps_privateaccess: Private-access rate inventory.
        section_fortisase_swg_sessions, section_fortisase_vpn_sessions: Location metadata.

    Output:
        One service per reported traffic location, enriched with known datacenter IDs.

    """
    for name in sorted(bandwidth_locations((section_fortisase_bps_privateaccess,),
                       section_fortisase_swg_sessions, section_fortisase_vpn_sessions)):
        yield Service(item=name)


def check_private_access(
    item: str,
    section_fortisase_bps_privateaccess: TrafficSection | None,
    section_fortisase_swg_sessions: SessionSection | None,
    section_fortisase_vpn_sessions: SessionSection | None,
) -> CheckResult:
    """
    Resolve the displayed datacenter identity before evaluating private-access rates.

    Input:
        item: Discovered location and datacenter display name.
        section_fortisase_bps_privateaccess: Private-access rate inventory.
        section_fortisase_swg_sessions, section_fortisase_vpn_sessions: Location metadata.

    Output:
        Valid rate results, or UNKNOWN when the required location mapping is unavailable.

    """
    names = bandwidth_locations((section_fortisase_bps_privateaccess,),
                               section_fortisase_swg_sessions, section_fortisase_vpn_sessions)
    location = names.get(item)
    if location is None or section_fortisase_bps_privateaccess is None:
        yield Result(state=State.UNKNOWN, summary='Private-access location or datacenter metadata unavailable')
        return
    yield from check_bps(location, section_fortisase_bps_privateaccess)


# Each declaration binds its parser and check together to keep their identifiers aligned.
agent_section_bps_privateaccess = _section('fortisase_bps_privateaccess')
check_plugin_bps_privateaccess = CheckPlugin(
    name='fortisase_bps_privateaccess', service_name='FortiSASE Private Access Bandwidth %s',
    sections=['fortisase_bps_privateaccess', 'fortisase_swg_sessions', 'fortisase_vpn_sessions'],
    discovery_function=discover_private_access, check_function=check_private_access)
agent_section_bps_inboundthinedge, check_plugin_bps_inboundthinedge = rate_registration('inboundthinedge', 'Thin Edge')
agent_section_bps_fortiextender, check_plugin_bps_fortiextender = rate_registration('fortiextender', 'FortiExtender')
agent_section_bps_fortigate, check_plugin_bps_fortigate = rate_registration('fortigate', 'FortiGate')
