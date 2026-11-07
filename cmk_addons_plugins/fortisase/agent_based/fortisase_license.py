"""
Monitor licensed, used and free FortiSASE endpoint seats.
"""
import math
from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State
from ..lib.common import parse_license


def discover_license(section):
    """
    Discover the seat allocation service when its section is returned.

    Input:
        section: Parsed license seat allocation.

    Output:
        One license service, including an invalid response requiring attention.

    """
    yield Service()


def check_license(section):
    """
    Evaluate seat usage without conflating missing data and zero capacity.

    Input:
        section: Validated licensed and used seat counts.

    Output:
        Counts and usage; WARN at 90 percent, CRIT at 100 percent, WARN for zero capacity.

    """
    if section.seats is None or section.used is None:
        yield Result(state=State.UNKNOWN, summary='Missing or invalid license seat data')
        return
    seats, used = section.seats, section.used
    usage = used / seats * 100 if seats else None
    if usage is not None and not math.isfinite(usage):
        yield Result(state=State.UNKNOWN, summary='Invalid license seat utilization')
        return
    free = max(0, seats - used)
    if usage is None:
        state = State.CRIT if used else State.WARN
        summary = f'No licensed seats, used: {used}'
    else:
        state = State.CRIT if usage >= 100 else State.WARN if usage >= 90 else State.OK
        summary = f'Seats: {seats}, used: {used}, free: {free}, utilization: {usage:.1f}%'
    yield Result(state=state, summary=summary)
    yield Metric('fortisase_license_seats', seats)
    yield Metric('fortisase_license_used', used)
    yield Metric('fortisase_license_free', free)
    if usage is not None:
        yield Metric('fortisase_license_usage', usage, levels=(90, 100))


agent_section_fortisase_license = AgentSection(name='fortisase_license', parse_function=parse_license)
check_plugin_fortisase_license = CheckPlugin(
    name='fortisase_license', service_name='FortiSASE License',
    discovery_function=discover_license, check_function=check_license)
