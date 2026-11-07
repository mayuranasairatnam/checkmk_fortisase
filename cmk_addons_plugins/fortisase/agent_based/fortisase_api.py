"""
Report collection coverage even when endpoint queries fail.
"""
from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State
from ..lib.common import number, parse_json


def discover_api(section):
    """
    Discover the singleton API collection status service.

    Input:
        section: Parsed agent data for the registered section.

    Output:
        Yields exactly one Checkmk Service without an item.

    """
    yield Service()


def check_api(section):
    """
    Evaluate API collection coverage and report query errors.

    Input:
        section: Parsed agent data for the registered section.

    Output:
        Yields status and collection duration; WARN for partial failures and CRIT for total/auth failures.

    """
    if (not isinstance(section, dict) or not isinstance(section.get('errors'), list)
            or not isinstance(section.get('successful'), int)
            or not isinstance(section.get('total'), int) or section['total'] <= 0
            or not 0 <= section['successful'] <= section['total']):
        yield Result(state=State.UNKNOWN, summary='Missing or invalid API collection status')
        return
    errors = section['errors']
    successful = section.get('successful', 0)
    total = section.get('total', 0)
    state = State.OK
    if errors:
        state = State.CRIT if section.get('authentication_failed') or not successful else State.WARN
    if errors:
        summary = f'API requests successful: {successful}/{total}, failed: {len(errors)}'
    else:
        summary = f'All {total} API requests successful'
    details = '\n'.join(str(error) for error in errors) or None
    yield Result(state=state, summary=summary, details=details)
    duration = number(section.get('duration'))
    if duration is not None:
        yield Metric('fortisase_api_duration', duration)


agent_section_fortisase_api = AgentSection(name='fortisase_api', parse_function=parse_json)
check_plugin_fortisase_api = CheckPlugin(
    name='fortisase_api', service_name='FortiSASE API',
    discovery_function=discover_api, check_function=check_api)
