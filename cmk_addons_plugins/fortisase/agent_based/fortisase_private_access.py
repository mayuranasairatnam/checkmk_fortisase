"""
Monitor each private-access hub across all reporting FortiSASE nodes.
"""
from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State, check_levels
from ..lib.common import identifier, location_display_name, number, parse_json, payload_rows

DEFAULT_LEVELS = {
    'latency': ('fixed', (150.0, 300.0)),
    'jitter': ('fixed', (30.0, 50.0)),
    'packet_loss': ('fixed', (1.0, 5.0)),
}
SECTIONS = ['fortisase_private_access_connections', 'fortisase_private_access_health', 'fortisase_regions']


def parse_connections(string_table):
    """
    Map explicit hub sequence numbers to names and configured BGP peers.

    Input:
        string_table: JSON section rows with the service-connections hubs envelope.

    Output:
        Hub aliases mapped to tunnel keys, BGP peers and provisioning states; None for invalid or ambiguous data.

    """
    raw = parse_json(string_table)
    if not isinstance(raw, dict) or raw.get('code', 200) not in (0, 200, '200'):
        return None
    rows = raw.get('hubs')
    if not isinstance(rows, list):
        return None
    hubs = {}
    keys = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('config'), dict):
            return None
        seq = row.get('seq_num')
        name = identifier(row['config'].get('alias'))
        if type(seq) is not int or seq < 1 or not name or name in hubs or seq in keys:
            return None
        keys.add(seq)
        hubs[name] = {'key': f'hub{seq}', 'peer': identifier(row['config'].get('bgp_peer_ip')),
                      'state': identifier(row.get('config_state'))}
    return hubs


def parse_health(string_table):
    """
    Retain node identities and reject malformed or duplicate node records.

    Input:
        string_table: JSON section rows with per-node health, tunnel and BGP records.

    Output:
        Node records keyed by unique serial number; None for malformed or duplicate records.

    """
    rows = payload_rows(parse_json(string_table))
    if rows is None:
        return None
    nodes = {}
    for row in rows:
        if not isinstance(row, dict):
            return None
        serial = identifier(row.get('primaryKey'))
        if not serial or serial in nodes:
            return None
        nodes[serial] = row
    return nodes


def parse_regions(string_table):
    """
    Resolve node serial numbers to unambiguous city/datacenter labels.

    Input:
        string_table: Monitoring-only site records from admin/config.

    Output:
        Serial-to-label mapping; ambiguous or invalid identities are omitted.
    """
    grouped = {}
    for row in payload_rows(parse_json(string_table)) or []:
        if not isinstance(row, dict):
            continue
        serial = identifier(row.get('device_sn'))
        alias = identifier(row.get('region_alias'))
        datacenter = identifier(row.get('pop_airport_name'))
        if serial and alias:
            aliases, datacenters = grouped.setdefault(serial, (set(), set()))
            aliases.add(alias)
            if datacenter:
                datacenters.add(datacenter)
    return {serial: location_display_name(next(iter(aliases)), tuple(sorted(datacenters)))
            for serial, (aliases, datacenters) in grouped.items()
            if len(aliases) == 1 and len(datacenters) <= 1}


def discover_private_access(section_fortisase_private_access_connections,
                            section_fortisase_private_access_health, section_fortisase_regions=None):
    """
    Discover the three hub services from explicitly configured connections.

    Input:
        section_fortisase_private_access_connections: Parsed hub inventory, or None.
        section_fortisase_private_access_health: Parsed node health, or None.
        section_fortisase_regions: Optional serial-to-city/datacenter mapping.

    Output:
        One Service per configured hub alias; no services for an absent or empty inventory.

    """
    for name in section_fortisase_private_access_connections or {}:
        yield Service(item=name)


def hub_nodes(item, connections, health):
    """
    Resolve a configured hub without inventing a node-to-region association.

    Input:
        item: Discovered hub alias.
        connections: Parsed hub inventory, or None.
        health: Parsed node health, or None.

    Output:
        Hub configuration and node records; (None, None) when the requested hub cannot be resolved.

    """
    if connections is None or item not in connections:
        return None, None
    return connections[item], health


def state_result(value, good, bad):
    """
    Distinguish documented healthy, unhealthy and unrecognized status values.

    Input:
        value: API status value.
        good: Normalized healthy status strings.
        bad: Normalized unhealthy status strings.

    Output:
        OK for a healthy status, CRIT for an unhealthy status, otherwise UNKNOWN.

    """
    text = value.strip().lower() if isinstance(value, str) else ''
    return State.OK if text in good else State.CRIT if text in bad else State.UNKNOWN


def evaluate(item, connections, health, kind, params=None, regions=None):
    """
    Evaluate every reporting node and expose worst-case link measurements.

    Input:
        item: Hub alias.
        connections: Parsed hub inventory.
        health: Parsed per-node health.
        kind: vpn, bgp or health evaluation.
        params: Optional upper thresholds for latency, jitter and packet loss.
        regions: Optional serial-to-city/datacenter mapping.

    Output:
        Per-node status results, reporting-node count and worst-case link metrics with threshold results.

    """
    hub, nodes = hub_nodes(item, connections, health)
    if hub is None or not nodes:
        yield Result(state=State.UNKNOWN, summary='Missing or invalid private-access hub/node data')
        return
    config_state = hub['state'].lower()
    if config_state != 'success':
        state = State.CRIT if config_state in ('failed', 'failure', 'error') else State.UNKNOWN
        yield Result(state=state, summary=f'Hub configuration: {config_state or "missing"}')
    samples = {key: [] for key in ('latency', 'jitter', 'packet_loss')}
    for serial, node in nodes.items():
        location = (regions or {}).get(serial, serial)
        if kind == 'vpn':
            tunnels = node.get('vpnTunnel')
            value = tunnels.get(hub['key']) if isinstance(tunnels, dict) else None
            state = state_result(value, {'up'}, {'down'})
            label = f'Tunnel {hub["key"]}'
        elif kind == 'bgp':
            neighbors = node.get('bgpNeighbors')
            value = neighbors.get(hub['peer']) if isinstance(neighbors, dict) and hub['peer'] else None
            state = state_result(value, {'established'},
                                 {'idle', 'connect', 'active', 'opensent', 'openconfirm',
                                  'clearing', 'deleted', 'down'})
            label = f'BGP {hub["peer"] or "peer missing"}'
        else:
            health_data = node.get('health')
            link = health_data.get(hub['key']) if isinstance(health_data, dict) else None
            value = link.get('status') if isinstance(link, dict) else None
            state = state_result(value, {'up'}, {'down'})
            label = f'Link {hub["key"]}'
            for key, field in (('latency', 'latency'), ('jitter', 'jitter'), ('packet_loss', 'packetLoss')):
                measurement = number(link.get(field)) if isinstance(link, dict) else None
                if measurement is None or (key == 'packet_loss' and measurement > 100):
                    yield Result(state=State.UNKNOWN, summary=f'{location}: missing or invalid {field}', details=f'Node: {serial}')
                else:
                    samples[key].append(measurement)
        status = identifier(value) or 'missing'
        yield Result(state=state, summary=f'{location}: {label} {status}',
                     details=f'{location}: {label} {status}\nNode: {serial}')
    yield Metric('fortisase_private_access_nodes', len(nodes))
    if kind == 'health':
        for key, values in samples.items():
            if values:
                unit = '%' if key == 'packet_loss' else 'ms'
                yield from check_levels(max(values),
                    levels_upper=(params or {}).get(key, DEFAULT_LEVELS[key]),
                    metric_name='fortisase_private_access_' + key,
                    label='Maximum ' + key.replace('_', ' '),
                    render_func=lambda value, unit=unit: f'{value:.2f} {unit}')


def check_vpn(item, section_fortisase_private_access_connections, section_fortisase_private_access_health,
              section_fortisase_regions=None):
    """
    Check only the configured hub tunnel on every reporting node.

    Input:
        item: Hub alias.
        section_fortisase_private_access_connections: Parsed hub inventory.
        section_fortisase_private_access_health: Parsed node health.
        section_fortisase_regions: Optional serial-to-city/datacenter mapping.

    Output:
        VPN status results for the configured hub tunnel and the reporting-node metric.

    """
    yield from evaluate(item, section_fortisase_private_access_connections,
                        section_fortisase_private_access_health, 'vpn', regions=section_fortisase_regions)


def check_bgp(item, section_fortisase_private_access_connections, section_fortisase_private_access_health,
              section_fortisase_regions=None):
    """
    Check the configured BGP neighbor on every reporting node.

    Input:
        item: Hub alias.
        section_fortisase_private_access_connections: Parsed hub inventory.
        section_fortisase_private_access_health: Parsed node health.
        section_fortisase_regions: Optional serial-to-city/datacenter mapping.

    Output:
        BGP neighbor state results and the reporting-node metric; UNKNOWN for unavailable peers.

    """
    yield from evaluate(item, section_fortisase_private_access_connections,
                        section_fortisase_private_access_health, 'bgp', regions=section_fortisase_regions)


def check_health(item, params, section_fortisase_private_access_connections,
                 section_fortisase_private_access_health, section_fortisase_regions=None):
    """
    Check hub link status and configurable latency, jitter and loss thresholds.

    Input:
        item: Hub alias.
        params: Configured upper latency, jitter and packet-loss thresholds.
        section_fortisase_private_access_connections: Parsed hub inventory.
        section_fortisase_private_access_health: Parsed node health.
        section_fortisase_regions: Optional serial-to-city/datacenter mapping.

    Output:
        Link status results and worst-case measurements; UNKNOWN diagnostics for missing or invalid data.

    """
    yield from evaluate(item, section_fortisase_private_access_connections,
                        section_fortisase_private_access_health, 'health', params, section_fortisase_regions)


agent_section_private_access_connections = AgentSection(
    name=SECTIONS[0], parse_function=parse_connections)
agent_section_private_access_health = AgentSection(name=SECTIONS[1], parse_function=parse_health)
agent_section_regions = AgentSection(name=SECTIONS[2], parse_function=parse_regions)
check_plugin_private_access_vpn = CheckPlugin(
    name='fortisase_private_access_vpn', sections=SECTIONS,
    service_name='FortiSASE Private Access %s VPN Status',
    discovery_function=discover_private_access, check_function=check_vpn)
check_plugin_private_access_bgp = CheckPlugin(
    name='fortisase_private_access_bgp', sections=SECTIONS,
    service_name='FortiSASE Private Access %s BGP Status',
    discovery_function=discover_private_access, check_function=check_bgp)
check_plugin_private_access_link = CheckPlugin(
    name='fortisase_private_access_link', sections=SECTIONS,
    service_name='FortiSASE Private Access %s Link Health',
    discovery_function=discover_private_access, check_function=check_health,
    check_default_parameters=DEFAULT_LEVELS, check_ruleset_name='fortisase_private_access')
