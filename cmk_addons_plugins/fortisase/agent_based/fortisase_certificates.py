"""
FortiSASE remote certificate discovery and lifetime checks using normalized UTC dates.
"""
import time
from collections.abc import Mapping

from cmk.agent_based.v2 import (
    AgentSection, CheckPlugin, CheckResult, DiscoveryResult, Result, Service, State, check_levels,
)

from ..lib.common import CertificateSection, parse_certificates


def discover_certs(section: CertificateSection) -> DiscoveryResult:
    """
    Discover remote certificates with explicit service identities.

    Input:
        section: Indexed certificates and response-level validation errors.

    Output:
        Yields one service per identified remote certificate, including invalid expiry dates.

    """
    for item in section.certificates:
        yield Service(item=item)


def check_certs(item: str, params: Mapping[str, object], section: CertificateSection) -> CheckResult:
    """
    Evaluate remaining certificate lifetime at the current check time.

    Input:
        item: Discovered certificate name and optional common name.
        params: Configured lower lifetime levels in days.
        section: Certificates with normalized UTC expiry timestamps.

    Output:
        Yields lifetime results and a metric, or UNKNOWN for invalid or missing certificate data.

    """
    certificate = section.certificates.get(item)
    # Keep already discovered certificate items checkable until rediscovery.
    if certificate is None and item.startswith('FortiSASE (') and item.endswith(')'):
        certificate = section.certificates.get(item.removeprefix('FortiSASE '))
    if certificate is None:
        yield Result(state=State.UNKNOWN, summary='Certificate not found in agent data')
        return
    if section.errors:
        yield Result(state=State.UNKNOWN, summary='Invalid certificate data', details='\n'.join(section.errors))
    if certificate.expires_at is None:
        yield Result(state=State.UNKNOWN, summary='Missing or invalid certificate expiry')
        return
    days = (certificate.expires_at - time.time()) / 86400
    yield from check_levels(
        days, levels_lower=params.get('days_remaining', ('fixed', (30, 14))),
        metric_name='fortisase_cert_days_remaining', label='Days remaining',
        render_func=lambda value: f'{value:.1f} days',
    )
    if certificate.common_name:
        yield Result(state=State.OK, notice=f'CN: {certificate.common_name}')


agent_section_remote_certificate = AgentSection(
    name='fortisase_remote_certificate', parse_function=parse_certificates)
check_plugin_remote_certificate = CheckPlugin(
    name='fortisase_remote_certificate', service_name='FortiSASE Certificate %s',
    discovery_function=discover_certs, check_function=check_certs,
    check_default_parameters={'days_remaining': ('fixed', (30, 14))},
    check_ruleset_name='fortisase_cert_expiry')
