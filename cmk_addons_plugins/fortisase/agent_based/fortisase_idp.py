"""
Monitor FortiSASE identity providers using the same evaluation as FortiClient EMS.
"""
from datetime import datetime, timezone
import math

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State, check_levels
from ..lib.common import identifier, parse_json

DEFAULT_PARAMETERS = {
    'offline_state': 'crit', 'connector_state': 'crit', 'error_state': 'crit',
    'sync_age': ('fixed', (86400.0, 172800.0)),
}

def configured_state(value):
    """
    Translate the ruleset's state choice into an Agent-based API state.

    Input:
        value: ok, warn or crit from the Setup rule.
    Output:
        The corresponding Checkmk State.
    """
    return {'ok': State.OK, 'warn': State.WARN, 'crit': State.CRIT}[value]

def number(value):
    """
    Read a finite, non-negative measurement without substituting a default.

    Input:
        value: Number or numeric string from EMS.
    Output:
        A float; raises ValueError for missing, boolean or invalid values.
    """
    if value is None or isinstance(value, bool):
        raise ValueError('Missing or invalid measurement')
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError('Missing or invalid measurement') from None
    if not math.isfinite(result) or result < 0:
        raise ValueError('Missing or invalid measurement')
    return result

def flag(value):
    """
    Normalize EMS boolean fields, preserving an unknown state.

    Input:
        value: Boolean, 0/1, or a corresponding boolean string.
    Output:
        True, False, or None when the API value is absent or unsupported.
    """
    if value is True or value in (1, '1', 'true', 'True'):
        return True
    if value is False or value in (0, '0', 'false', 'False'):
        return False
    return None

def moment(value):
    """
    Parse an EMS ISO date or timestamp in UTC.

    Input:
        value: ISO date or datetime; timezone-less timestamps are treated as UTC.
    Output:
        An aware UTC datetime; raises ValueError for invalid dates.
    """
    if not isinstance(value, str) or not value:
        raise ValueError('Missing or invalid date')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except ValueError:
        raise ValueError('Missing or invalid date') from None

def idp_identity(entry):
    """
    Identify an EMS provider even when its connector alias is empty.

    Input:
        entry: Provider with optional alias, domain, group path and identifiers.
    Output:
        Display name without GUIDs, or None for an unidentifiable response row.
        Duplicate display names are reported as ambiguous by the checks.
    """
    if not isinstance(entry, dict):
        return None
    conn = entry.get('connection_info')
    domain = entry.get('domain_info')
    group = entry.get('group_info')
    conn = conn if isinstance(conn, dict) else {}
    domain = domain if isinstance(domain, dict) else {}
    group = group if isinstance(group, dict) else {}
    name = next((value.strip() for value in (conn.get('alias'), entry.get('name'),
                 domain.get('name'), group.get('path')) if isinstance(value, str) and value.strip()), None)
    ident = entry.get('id')
    if ident is not None:
        return f'{name} (ID {ident})' if name else f'ID {ident}'
    # GUIDs belong in service output. Never combine providers sharing a name;
    # the normal object lookup reports ambiguous names as UNKNOWN.
    guid = entry.get('guid') or domain.get('guid')
    if isinstance(guid, str) and guid.strip():
        return name or 'Unnamed provider'
    return name

def check_idp_data(record, params, entry):
    """
    Evaluate IDP/connector availability, synchronization health and age.

    Input:
        record: Tenant record; params: States and maximum sync age; entry: IDP.
    Output:
        Connection/sync results plus device, user, progress and sync-age metrics.
    """
    status, conn = entry.get('status') or {}, entry.get('connection_info') or {}
    domain = (entry.get('domain_info') or {}).get('name')
    yield Result(state=State.OK, summary=f'Domain: {domain or "unspecified"}')
    guid = entry.get('guid') or (entry.get('domain_info') or {}).get('guid')
    if isinstance(guid, str) and guid.strip():
        yield Result(state=State.OK, summary=f'GUID: {guid}')
    for title, value, setting in (('IDP', status.get('online'), 'offline_state'),
                                  ('Connector', conn.get('conn_online'), 'connector_state')):
        online = flag(value)
        state = State.UNKNOWN if online is None else State.OK if online else configured_state(params.get(setting, 'crit'))
        yield Result(state=state, summary=f'{title}: ' + ('unknown' if online is None else 'online' if online else 'offline'))
    if status.get('last_error'):
        yield Result(state=configured_state(params.get('error_state', 'crit')), summary='Synchronization error', details=str(status['last_error']))
    else:
        yield Result(state=State.OK, summary='No synchronization error')
    for key, metric, title in (('total_devices', 'fortisase_idp_devices', 'Devices'), ('total_users', 'fortisase_idp_users', 'Users')):
        try:
            value = number(entry.get(key))
            yield Metric(metric, value)
            yield Result(state=State.OK, summary=f'{title}: {value:g}')
        except ValueError:
            yield Result(state=State.UNKNOWN, summary=f'{title}: missing or invalid')
    try:
        progress = number(status.get('sync_progress'))
        if progress > 100:
            raise ValueError('Sync progress exceeds 100%')
        yield Metric('fortisase_idp_sync_progress', progress)
        yield Result(state=State.OK, summary=f'Sync progress: {progress:g}%')
    except ValueError:
        yield Result(state=State.UNKNOWN, summary='Sync progress: missing or invalid')
    last = moment(status.get('last_success_enumerated'))
    age = (datetime.now(timezone.utc) - last).total_seconds()
    if age < 0:
        raise ValueError('Last successful sync lies in the future')
    yield Result(state=State.OK, summary=f'Last successful sync: {last.isoformat()}')
    yield from check_levels(age, levels_upper=params.get('sync_age', ('fixed', (86400.0, 172800.0))),
                            metric_name='fortisase_idp_sync_age', label='Sync age', render_func=lambda v: f'{v / 3600:.1f} hours')


def parse_idps(string_table):
    """
    Validate the result envelope and retain duplicate identities for diagnostics.

    Input:
        string_table: JSON section containing result.retval and an IDP record list.

    Output:
        Provider records grouped by display identity and inventory validity.
    """
    raw = parse_json(string_table)
    if isinstance(raw, dict) and 'data' in raw and (raw['data'] is None or raw['data'] == {}):
        raw = {**raw, 'data': []}
    result = raw.get('result') if isinstance(raw, dict) else None
    if (not isinstance(raw, dict) or raw.get('code', 200) not in (0, 200, '200')
            or not isinstance(result, dict) or type(result.get('retval')) is not int
            or result['retval'] != 1 or not isinstance(raw.get('data'), list)):
        return {'valid': False, 'entries': {}, 'count': None}
    entries = {}
    valid = True
    for entry in raw['data']:
        name = idp_identity(entry)
        if not name or identifier(name) != name:
            valid = False
            continue
        entries.setdefault(name, []).append(entry)
        if len(entries[name]) > 1:
            valid = False
    return {'valid': valid, 'entries': entries, 'count': len(raw['data'])}


def discover_idps(section):
    """
    Discover readable provider names without including GUIDs in service items.

    Input:
        section: Parsed provider inventory with names and records.

    Output:
        One Service per provider identity, including ambiguous discovered items.
    """
    for name in section['entries']:
        yield Service(item=name)


def discover_summary(section):
    """
    Keep the inventory service visible for empty or invalid API responses.

    Input:
        section: Parsed provider inventory.

    Output:
        One inventory summary Service.
    """
    yield Service()


def check_summary(section):
    """
    Report empty inventories and invalid or ambiguous provider identities.

    Input:
        section: Validated provider inventory and identity diagnostics.

    Output:
        Inventory state and provider count when the response is valid.
    """
    if not section['valid']:
        yield Result(state=State.UNKNOWN, summary='Provider identities missing or ambiguous; check the IDP API response')
        return
    count = section['count']
    yield Result(state=State.OK, summary=f'{count} identity provider(s) returned'
                 if count else 'No identity providers returned for this tenant')
    yield Metric('fortisase_idp_count', count)


def check_idp(item, params, section):
    """
    Apply EMS-compatible provider checks and preserve explicit validation errors.

    Input:
        item: Provider identity; params: Configured states and sync-age levels.
        section: Parsed IDP records keyed by their discovered identity.

    Output:
        Domain/GUID, availability, sync status and FortiSASE-prefixed metrics.
    """
    entries = section['entries'].get(item, [])
    if len(entries) != 1:
        yield Result(state=State.UNKNOWN, summary='Identity provider missing or ambiguous')
        return
    entry = entries[0]
    if any(entry.get(key) is not None and not isinstance(entry[key], dict)
           for key in ('status', 'connection_info', 'domain_info')):
        yield Result(state=State.UNKNOWN, summary='Invalid identity provider status structure')
        return
    try:
        yield from check_idp_data(None, params, entry)
    except (ValueError, OverflowError) as error:
        yield Result(state=State.UNKNOWN, summary=str(error) or 'Invalid identity provider data')


agent_section_fortisase_idp = AgentSection(name='fortisase_idp', parse_function=parse_idps)
check_plugin_fortisase_idp = CheckPlugin(
    name='fortisase_idp', service_name='FortiSASE IDP %s',
    discovery_function=discover_idps, check_function=check_idp,
    check_ruleset_name='fortisase_idp', check_default_parameters=DEFAULT_PARAMETERS)
check_plugin_fortisase_idp_summary = CheckPlugin(
    name='fortisase_idp_summary', sections=['fortisase_idp'],
    service_name='FortiSASE Identity Providers',
    discovery_function=discover_summary, check_function=check_summary)
