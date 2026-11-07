"""
FortiSASE point-of-presence bandwidth shared by VPN and web-gateway traffic.
"""
from cmk.agent_based.v2 import (
    AgentSection, CheckPlugin, CheckResult, DiscoveryResult, Metric, Result, Service, State, render,
)
from ..lib.common import SessionSection, TrafficSection, bandwidth_locations, parse_traffic


def discover_pop(
    section_fortisase_bps_inbounduser: TrafficSection | None,
    section_fortisase_bps_outbound: TrafficSection | None,
    section_fortisase_swg_sessions: SessionSection | None = None,
    section_fortisase_vpn_sessions: SessionSection | None = None,
) -> DiscoveryResult:
    """
    Discover each reported PoP once across both regional traffic inventories.

    Input:
        section_fortisase_bps_inbounduser: Optional regional user-access rates.
        section_fortisase_bps_outbound: Optional regional outbound rates.
        section_fortisase_swg_sessions: Web gateway inventory supplying datacenter IDs.
        section_fortisase_vpn_sessions: VPN inventory supplying datacenter IDs.

    Output:
        One service per location, independently of active SWG or VPN sessions.

    """
    locations = bandwidth_locations(
        (section_fortisase_bps_inbounduser, section_fortisase_bps_outbound),
        section_fortisase_swg_sessions, section_fortisase_vpn_sessions)
    for location in sorted(locations):
        yield Service(item=location)


def check_pop_source(item: str, caption: str, metric_prefix: str, section: TrafficSection | None) -> CheckResult:
    """
    Report one PoP traffic source without attributing it to a session protocol.

    Input:
        item: PoP location label from discovery.
        caption: User-facing traffic source description.
        metric_prefix: Persistent metric prefix for this source.
        section: Normalized rate inventory, or None when collection failed.

    Output:
        Available rate metrics and a grouped summary; incomplete sources report UNKNOWN.

    """
    region = section.regions.get(item) if section is not None else None
    if region is None:
        yield Result(state=State.UNKNOWN, summary=f'{caption}: bandwidth data unavailable')
        return
    issues = (*section.errors, *region.errors)
    if issues:
        yield Result(state=State.UNKNOWN, summary=f'{caption}: invalid bandwidth data',
                     details='\n'.join(issues))
    readings = []
    for suffix, label, value in (('rx', 'receive', region.rx), ('tx', 'transmit', region.tx)):
        if value is not None:
            readings.append(f'{label} {render.networkbandwidth(value / 8)}')
            yield Metric(f'{metric_prefix}_{suffix}', value)
    if not readings and region.bps is not None:
        readings.append(f'traffic rate {render.networkbandwidth(region.bps / 8)}')
        yield Metric(metric_prefix, region.bps)
    if readings:
        message = f'{caption}: ' + ' / '.join(readings)
        yield Result(state=State.OK, summary=message,
                     details=f'{message}. Location: {item}. Shared regional PoP traffic; '
                             'the API does not separate these rates into SWG and VPN traffic. '
                             'Receive/transmit directions follow the API.')
    elif not issues:
        yield Result(state=State.UNKNOWN, summary=f'{caption}: no bandwidth samples')


def check_pop(
    item: str,
    section_fortisase_bps_inbounduser: TrafficSection | None,
    section_fortisase_bps_outbound: TrafficSection | None,
    section_fortisase_swg_sessions: SessionSection | None = None,
    section_fortisase_vpn_sessions: SessionSection | None = None,
) -> CheckResult:
    """
    Evaluate shared user-access and outbound bandwidth for a single PoP.

    Input:
        item: Discovered location label.
        section_fortisase_bps_inbounduser: User-access rate inventory.
        section_fortisase_bps_outbound: Outbound rate inventory.
        section_fortisase_swg_sessions: Web gateway location metadata.
        section_fortisase_vpn_sessions: VPN location metadata.

    Output:
        Independent source summaries and metrics without summing overlapping traffic paths.

    """
    locations = bandwidth_locations(
        (section_fortisase_bps_inbounduser, section_fortisase_bps_outbound),
        section_fortisase_swg_sessions, section_fortisase_vpn_sessions)
    location = locations.get(item)
    if location is None:
        yield Result(state=State.UNKNOWN, summary='PoP location or datacenter metadata unavailable')
        return
    yield from check_pop_source(location, 'User access', 'fortisase_inbounduser_bps', section_fortisase_bps_inbounduser)
    yield from check_pop_source(location, 'Outbound', 'fortisase_outbound_bps', section_fortisase_bps_outbound)


agent_section_pop_user_access = AgentSection(name='fortisase_bps_inbounduser', parse_function=parse_traffic)
agent_section_pop_outbound = AgentSection(name='fortisase_bps_outbound', parse_function=parse_traffic)
check_plugin_fortisase_pop = CheckPlugin(
    name='fortisase_pop', service_name='FortiSASE VPN/SWG Bandwidth %s',
    sections=['fortisase_bps_inbounduser', 'fortisase_bps_outbound',
              'fortisase_swg_sessions', 'fortisase_vpn_sessions'],
    discovery_function=discover_pop, check_function=check_pop)
