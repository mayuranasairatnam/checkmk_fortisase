"""
Shared FortiSASE data models, response normalization and session evaluation.
"""
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from cmk.agent_based.v2 import CheckResult, DiscoveryResult, Metric, Result, Service, State, render


# JSON, identifiers and numeric validation.


def parse_json(string_table: list[list[str]]) -> dict[str, object] | list[object]:
    """
    Parse the JSON agent payload while rejecting unsupported root types.

    Input:
        string_table: Checkmk section rows containing the JSON agent payload.

    Output:
        Decoded dictionary or list; an empty dictionary for missing, malformed or scalar input.

    """
    if not string_table:
        return {}
    try:
        value = json.loads(string_table[0][0])
        return value if isinstance(value, (dict, list)) else {}
    except (ValueError, IndexError, TypeError):
        return {}


def number(value: object) -> float | None:
    """
    Convert a measurement to a finite non-negative floating-point value.

    Input:
        value: Raw value to validate or convert.

    Output:
        Finite float including zero, or None for booleans, missing, invalid or negative values.

    """
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        result = float(value)
        return result if math.isfinite(result) and result >= 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def payload_rows(raw: object, *, traffic: bool = False) -> list[object] | None:
    """
    Unwrap API data while distinguishing empty results from invalid envelopes.

    Input:
        raw: Decoded JSON payload.
        traffic: Whether the data may contain a datasets wrapper.

    Output:
        Record list including an empty successful list, or None for invalid input.

    """
    if isinstance(raw, dict):
        if raw.get('code', 200) not in (0, 200, '200'):
            return None
        raw = raw.get('data')
    if traffic and isinstance(raw, dict):
        raw = raw.get('datasets')
    return raw if isinstance(raw, list) else None


def identifier(value: object) -> str:
    """
    Validate an API item identifier without inventing positional names.

    Input:
        value: Region ID, label, certificate name or primary key.

    Output:
        Non-empty single-line string, or an empty string for unsupported values.

    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ''
    result = str(value).strip()
    return result if result and not any(ord(char) < 32 for char in result) else ''


def total(values: list[float]) -> float | None:
    """
    Sum validated samples while rejecting floating-point overflow.

    Input:
        values: Finite non-negative numeric samples.

    Output:
        Finite total, including zero for an empty list, or None on overflow.

    """
    try:
        result = math.fsum(values)
    except OverflowError:
        return None
    return result if math.isfinite(result) else None


# Traffic models and regional rate normalization.


@dataclass(frozen=True)
class Throughput:
    """
    Directional measurements for one traffic region.

    Input:
        rx, tx, bps: Optional finite rates in bits per second.
        errors: Validation failures associated with this region.

    Output:
        Immutable regional throughput record; None distinguishes absent data from zero.

    """
    rx: float | None = None
    tx: float | None = None
    bps: float | None = None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrafficSection:
    """
    Validated regional rates for one traffic type.

    Input:
        regions: Regional throughput indexed by the API label.
        errors: Structural or measurement errors in the response.

    Output:
        Regional rate inventory shared by bandwidth and session checks.

    """
    regions: Mapping[str, Throughput] = field(default_factory=dict)
    errors: tuple[str, ...] = ()


def parse_traffic(string_table: list[list[str]]) -> TrafficSection:
    """
    Normalize final traffic samples once for all consuming checks.

    Input:
        string_table: JSON section rows emitted by the special agent.

    Output:
        Indexed regional rates with explicit structural and measurement diagnostics.

    """
    rows = payload_rows(parse_json(string_table), traffic=True)
    if rows is None:
        return TrafficSection(errors=('Invalid traffic response',))
    grouped: dict[str, dict[str, list[float]]] = {}
    regional_errors: dict[str, list[str]] = {}
    errors: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            errors.append('Invalid traffic dataset')
            continue
        label = identifier(row.get('name') or row.get('label') or row.get('id'))
        parts = label.split(':')
        region = parts[1].strip() if len(parts) >= 2 else label
        direction = parts[0].strip().lower() if len(parts) >= 2 else ''
        if not region:
            errors.append('Traffic dataset has no region identifier')
            continue
        bucket = grouped.setdefault(region, {})
        issues = regional_errors.setdefault(region, [])
        points = row.get('data')
        if not isinstance(points, list) or not points or not isinstance(points[-1], dict):
            issues.append('No valid final traffic sample')
            errors.append('Traffic dataset has no valid final sample')
            continue
        point = points[-1]
        if 'bps' in point:
            rate = number(point['bps'])
            if rate is None:
                issues.append('Invalid throughput sample')
            else:
                key = 'rx' if direction.startswith('receive') else 'tx' if direction.startswith('transmit') else 'bps'
                bucket.setdefault(key, []).append(rate)
    regions = {}
    for region, values in grouped.items():
        sums = {key: total(samples) for key, samples in values.items()}
        issues = regional_errors[region]
        if any(value is None for value in sums.values()):
            issues.append('Throughput total exceeds numeric range')
        if sums or issues:
            regions[region] = Throughput(**sums, errors=tuple(dict.fromkeys(issues)))
    return TrafficSection(regions=regions, errors=tuple(dict.fromkeys(errors)))


# Session models and inventory normalization.


@dataclass(frozen=True)
class SessionRegion:
    """
    Normalized measurements for one session region.

    Input:
        label: Display label used to join the traffic region.
        count: Number of valid session records, or None for malformed records.
        received, sent: Valid byte totals, or None for incomplete counters.
        errors: Reasons why measurements are unavailable.

    Output:
        Immutable session record preserving valid independent measurements.

    """
    label: str
    count: int | None
    received: float | None
    sent: float | None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class SessionSection:
    """
    Indexed session regions with response-level validation errors.

    Input:
        regions: Session records indexed by region ID.
        errors: Invalid or duplicate region identifiers and envelope errors.

    Output:
        Session section shared by SWG and VPN callbacks.

    """
    regions: Mapping[str, SessionRegion] = field(default_factory=dict)
    errors: tuple[str, ...] = ()


def session_region(row: Mapping[str, object], label: str) -> SessionRegion:
    """
    Validate session counts and each byte direction independently.

    Input:
        row: API region containing its session list.
        label: Region label used to join throughput.

    Output:
        Session totals; malformed or missing values remain unavailable rather than zero.

    """
    sessions = row.get('data')
    if not isinstance(sessions, list) or any(not isinstance(record, dict) for record in sessions):
        return SessionRegion(label, None, None, None, ('Missing or invalid session list',))
    totals: dict[str, float | None] = {}
    errors = []
    for direction, key in (('received', 'receivedBytes'), ('sent', 'sentBytes')):
        samples = [number(record.get(key)) for record in sessions]
        valid = [sample for sample in samples if sample is not None]
        value = total(valid) if len(valid) == len(samples) else None
        totals[direction] = value
        if value is None:
            errors.append(f'Missing or invalid {direction} byte counters')
    return SessionRegion(label, len(sessions), totals['received'], totals['sent'], tuple(errors))


def parse_sessions(string_table: list[list[str]]) -> SessionSection:
    """
    Index session regions and reject ambiguous service identities.

    Input:
        string_table: JSON section rows emitted by the special agent.

    Output:
        Parsed regional sessions and response-level validation errors.

    """
    rows = payload_rows(parse_json(string_table))
    if rows is None:
        return SessionSection(errors=('Invalid sessions response',))
    regions = {}
    errors = []
    for row in rows:
        if not isinstance(row, dict):
            errors.append('Invalid session region record')
            continue
        item = identifier(row.get('region') or row.get('regionLabel'))
        if not item:
            errors.append('Session region has no identifier')
            continue
        if item in regions:
            errors.append(f'Duplicate session region: {item}')
            continue
        label = identifier(row.get('regionLabel')) or item
        regions[item] = session_region(row, label)
    return SessionSection(regions, tuple(dict.fromkeys(errors)))


# Certificate models and UTC expiry handling.


@dataclass(frozen=True)
class Certificate:
    """
    Certificate identity and normalized UTC expiry.

    Input:
        common_name: Subject CN for display.
        expires_at: UTC expiry timestamp, or None for an invalid date.

    Output:
        Immutable certificate record; remaining lifetime is evaluated at check time.

    """
    common_name: str
    expires_at: float | None


@dataclass(frozen=True)
class CertificateSection:
    """
    Indexed remote certificates with structural validation errors.

    Input:
        certificates: Certificate records indexed by the established service item.
        errors: Invalid identifiers, duplicates or response envelope errors.

    Output:
        Certificate section used for discovery and lifetime checks.

    """
    certificates: Mapping[str, Certificate] = field(default_factory=dict)
    errors: tuple[str, ...] = ()


def expiry_timestamp(value: object) -> float | None:
    """
    Normalize an ISO8601 expiry to a UTC epoch timestamp.

    Input:
        value: Certificate validTo string from the API.

    Output:
        UTC timestamp, or None for unsupported or invalid values; naive dates use UTC.

    """
    if not isinstance(value, str):
        return None
    try:
        expiry = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def parse_certificates(string_table: list[list[str]]) -> CertificateSection:
    """
    Normalize certificate metadata and validate unique service items.

    Input:
        string_table: JSON section rows emitted by the special agent.

    Output:
        Indexed certificates with normalized expiry and structural validation errors.

    """
    rows = payload_rows(parse_json(string_table))
    if rows is None:
        return CertificateSection(errors=('Invalid certificate response',))
    certificates = {}
    errors = []
    for row in rows:
        if not isinstance(row, dict):
            errors.append('Invalid certificate record')
            continue
        meta = row.get('$meta')
        info = meta.get('info') if isinstance(meta, dict) else None
        info = info if isinstance(info, dict) else {}
        subject = info.get('subject')
        cn = identifier(subject.get('CN')) if isinstance(subject, dict) else ''
        name = identifier(info.get('name') or row.get('primaryKey'))
        # The service prefix already identifies FortiSASE; retain the distinguishing CN.
        if name == 'FortiSASE' and cn and name != cn:
            item = f'({cn})'
        else:
            item = f'{name} ({cn})' if name and cn and name != cn else name or cn
        if not item:
            errors.append('Certificate has no identifier')
            continue
        if item in certificates:
            errors.append(f'Duplicate certificate: {item}')
            continue
        certificates[item] = Certificate(cn, expiry_timestamp(info.get('validTo')))
    return CertificateSection(certificates, tuple(dict.fromkeys(errors)))


# Shared session discovery and evaluation for SWG and VPN.


def location_display_name(label: str, datacenters: tuple[str, ...]) -> str:
    """
    Apply the common city/datacenter naming convention to reported location metadata.

    Input:
        label: Full API location label, including any country/provider qualifiers.
        datacenters: Confirmed datacenter identifiers associated with this location.

    Output:
        City (datacenter) when metadata is available, otherwise the original label.

    """
    return f'{label.split(" (", 1)[0]} ({", ".join(datacenters)})' if datacenters else label


def session_location_items(section: SessionSection | None) -> dict[str, str]:
    """
    Associate session service display names with their original API region keys.

    Input:
        section: Protocol-specific session inventory, or None on collection failure.

    Output:
        Display-name to region-key mapping using the same city/datacenter format as bandwidth.

    """
    if section is None:
        return {}
    return {location_display_name(region.label, (key,) if key != region.label else ()): key
            for key, region in section.regions.items()}


def discover_sessions(section: SessionSection | None) -> DiscoveryResult:
    """
    Discover uniquely identified regions independently of optional throughput.

    Input:
        section: Parsed SWG or VPN session data, or None when collection failed.

    Output:
        Yields one service per region named with its city and reported datacenter key.

    """
    for item in sorted(session_location_items(section)):
        yield Service(item=item)


def check_sessions(
    item: str,
    section_sessions: SessionSection | None,
) -> CheckResult:
    """
    Report protocol-specific session measurements independently of shared PoP bandwidth.

    Input:
        item: Discovered region identifier.
        section_sessions: Normalized SWG or VPN regions.

    Output:
        Yields valid metrics and UNKNOWN diagnostics for incomplete session measurements.

    """
    key = session_location_items(section_sessions).get(item, item)
    region = section_sessions.regions.get(key) if section_sessions is not None else None
    if region is None:
        yield Result(state=State.UNKNOWN, summary='Region not found in session data')
        return
    issues = (*section_sessions.errors, *region.errors)
    if issues:
        yield Result(state=State.UNKNOWN, summary='Invalid session data', details='\n'.join(issues))
    if region.count is not None:
        yield Result(state=State.OK, summary=f'Active sessions: {region.count} ({region.label})')
        yield Metric('fortisase_sessions', region.count)
    for value, label, metric in (
        (region.received, 'Data received by current sessions', 'fortisase_received_total'),
        (region.sent, 'Data sent by current sessions', 'fortisase_sent_total'),
    ):
        if value is not None:
            yield Result(state=State.OK, notice=f'{label}: {render.bytes(value)}')
            yield Metric(metric, value)


def bandwidth_locations(
    traffic: tuple[TrafficSection | None, ...],
    swg: SessionSection | None = None,
    vpn: SessionSection | None = None,
) -> dict[str, str]:
    """
    Associate API location labels with reported datacenter shortnames.

    Input:
        traffic: Rate inventories supplying the locations to discover.
        swg, vpn: Optional session inventories mapping readable labels to region IDs.

    Output:
        Display item to original location mapping. Known sites use City (datacenter);
        missing metadata retains the original API label without guessing an ID.

    """
    labels = {label for section in traffic if section is not None for label in section.regions}
    datacenters: dict[str, set[str]] = {}
    for section in (swg, vpn):
        if section is not None:
            for ident, region in section.regions.items():
                if ident != region.label:
                    datacenters.setdefault(region.label, set()).add(ident)
    candidates: dict[str, list[str]] = {}
    for label in sorted(labels):
        codes = sorted(datacenters.get(label, ()))
        name = location_display_name(label, tuple(codes))
        candidates.setdefault(name, []).append(label)
    result = {}
    for name, originals in candidates.items():
        for label in originals:
            # Preserve distinct API locations when shortened names would collide.
            display = name if len(originals) == 1 else f'{name} [{label}]'
            result[display] = label
    return result


@dataclass(frozen=True)
class LicenseSection:
    """
    Seat allocation returned by the EMS-backed FortiSASE seat endpoint.

    Input:
        seats: Licensed capacity, or None when the response is invalid.
        used: Used seats, or None when the response is invalid.

    Output:
        Validated counts with missing data distinguished from zero.

    """
    seats: int | None = None
    used: int | None = None


def parse_license(string_table):
    """
    Validate the seat endpoint's result envelope and non-negative integer counts.

    Input:
        string_table: JSON rows containing result.retval, data.seats and data.used.

    Output:
        Seat counts, or an invalid section without fabricated zeroes.

    """
    raw = parse_json(string_table)
    if not isinstance(raw, dict) or raw.get('code', 200) not in (0, 200, '200'):
        return LicenseSection()
    result, data = raw.get('result'), raw.get('data')
    if (not isinstance(result, dict) or type(result.get('retval')) is not int
            or result['retval'] != 1 or not isinstance(data, dict)):
        return LicenseSection()
    if any(type(data.get(key)) is not int or number(data[key]) is None for key in ('seats', 'used')):
        return LicenseSection()
    return LicenseSection(data['seats'], data['used'])
