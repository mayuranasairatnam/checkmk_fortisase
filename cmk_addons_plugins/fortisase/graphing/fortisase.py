"""
Declare the monitoring units, metric catalog and charts for normalized FortiSASE measurements.
"""
from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph, MinimalRange
from cmk.graphing.v1.metrics import Color, DecimalNotation, IECNotation, Metric, Unit

RATE_UNIT = Unit(DecimalNotation('bit/s'))
OCTET_UNIT = Unit(IECNotation('B'))
SESSION_UNIT = Unit(DecimalNotation(''))
LIFETIME_UNIT = Unit(DecimalNotation('days'))
DURATION_UNIT = Unit(DecimalNotation('s'))


def catalog_metric(identifier: str, caption: str, unit: Unit, color: Color) -> Metric:
    """
    Construct a metric from the package's shared display catalog.

    Input:
        identifier: Metric key emitted by a check and stored in performance data.
        caption: Measurement description shown in the Checkmk interface.
        unit: Rendering convention appropriate to the recorded numeric value.
        color: Palette selection for plotting this measurement.

    Output:
        Metric declaration exposed through an explicit module-level registration.

    """
    return Metric(name=identifier, title=Title(caption), unit=unit, color=color)


def catalog_graph(identifier: str, caption: str, *measurements: str) -> Graph:
    """
    Assemble related measurements into a chart with a zero-based display range.

    Input:
        identifier: Persistent graph key.
        caption: Chart heading displayed alongside the service.
        measurements: Ordered metric identifiers belonging to the same unit family.

    Output:
        Graph declaration containing the selected performance-data series.

    """
    return Graph(name=identifier, title=Title(caption), simple_lines=list(measurements),
                 minimal_range=MinimalRange(0, 1))


# Explicit exports allow Checkmk to discover the catalog without runtime registration.
metric_fortisase_bps = catalog_metric('fortisase_bps', 'Reported traffic rate', RATE_UNIT, Color.BLUE)
metric_fortisase_bps_rx = catalog_metric('fortisase_bps_rx', 'Received traffic rate', RATE_UNIT, Color.GREEN)
metric_fortisase_bps_tx = catalog_metric('fortisase_bps_tx', 'Transmitted traffic rate', RATE_UNIT, Color.BLUE)
metric_fortisase_sessions = catalog_metric('fortisase_sessions', 'Reported session count', SESSION_UNIT, Color.PURPLE)
metric_fortisase_received_total = catalog_metric('fortisase_received_total', 'Bytes received by current sessions', OCTET_UNIT, Color.GREEN)
metric_fortisase_sent_total = catalog_metric('fortisase_sent_total', 'Bytes sent by current sessions', OCTET_UNIT, Color.ORANGE)
metric_fortisase_cert_days_remaining = catalog_metric('fortisase_cert_days_remaining', 'Certificate lifetime remaining', LIFETIME_UNIT, Color.YELLOW)
metric_fortisase_api_duration = catalog_metric('fortisase_api_duration', 'Time spent collecting API resources', DURATION_UNIT, Color.PURPLE)
metric_fortisase_inbounduser_bps_rx = catalog_metric('fortisase_inbounduser_bps_rx', 'PoP user access receive rate', RATE_UNIT, Color.GREEN)
metric_fortisase_inbounduser_bps_tx = catalog_metric('fortisase_inbounduser_bps_tx', 'PoP user access transmit rate', RATE_UNIT, Color.LIGHT_GREEN)
metric_fortisase_outbound_bps_rx = catalog_metric('fortisase_outbound_bps_rx', 'PoP outbound receive rate', RATE_UNIT, Color.BLUE)
metric_fortisase_outbound_bps_tx = catalog_metric('fortisase_outbound_bps_tx', 'PoP outbound transmit rate', RATE_UNIT, Color.LIGHT_BLUE)

graph_fortisase_bps = catalog_graph('fortisase_bps', 'Reported traffic rate', 'fortisase_bps')
graph_fortisase_sessions_traffic = catalog_graph('fortisase_sessions_traffic', 'Current session byte totals', 'fortisase_received_total', 'fortisase_sent_total')
graph_fortisase_directional_throughput = catalog_graph('fortisase_directional_throughput', 'Regional traffic rates', 'fortisase_bps_rx', 'fortisase_bps_tx')
graph_fortisase_session_throughput = catalog_graph(
    'fortisase_session_throughput', 'PoP user-access and outbound rates',
    'fortisase_inbounduser_bps_rx', 'fortisase_inbounduser_bps_tx',
    'fortisase_outbound_bps_rx', 'fortisase_outbound_bps_tx')

metric_fortisase_inbounduser_bps = catalog_metric('fortisase_inbounduser_bps', 'PoP user access rate', RATE_UNIT, Color.GREEN)
metric_fortisase_outbound_bps = catalog_metric('fortisase_outbound_bps', 'PoP outbound rate', RATE_UNIT, Color.BLUE)

PERCENT_UNIT = Unit(DecimalNotation('%'))
metric_fortisase_license_seats = catalog_metric('fortisase_license_seats', 'Licensed seats', SESSION_UNIT, Color.BLUE)
metric_fortisase_license_used = catalog_metric('fortisase_license_used', 'Used seats', SESSION_UNIT, Color.ORANGE)
metric_fortisase_license_free = catalog_metric('fortisase_license_free', 'Free seats', SESSION_UNIT, Color.GREEN)
metric_fortisase_license_usage = catalog_metric('fortisase_license_usage', 'Seat utilization', PERCENT_UNIT, Color.PURPLE)
graph_fortisase_license_seats = catalog_graph(
    'fortisase_license_seats', 'License seat allocation',
    'fortisase_license_seats', 'fortisase_license_used', 'fortisase_license_free')
graph_fortisase_license_usage = catalog_graph(
    'fortisase_license_usage', 'License seat utilization', 'fortisase_license_usage')


metric_private_access_latency = catalog_metric('fortisase_private_access_latency', 'Maximum hub latency', Unit(DecimalNotation('ms')), Color.BLUE)
metric_private_access_jitter = catalog_metric('fortisase_private_access_jitter', 'Maximum hub jitter', Unit(DecimalNotation('ms')), Color.PURPLE)
metric_private_access_loss = catalog_metric('fortisase_private_access_packet_loss', 'Maximum hub packet loss', Unit(DecimalNotation('%')), Color.ORANGE)
metric_private_access_nodes = catalog_metric('fortisase_private_access_nodes', 'Reporting nodes', SESSION_UNIT, Color.GREEN)
graph_private_access_latency = catalog_graph('fortisase_private_access_latency', 'Hub latency', 'fortisase_private_access_latency')
graph_private_access_jitter = catalog_graph('fortisase_private_access_jitter', 'Hub jitter', 'fortisase_private_access_jitter')
graph_private_access_loss = catalog_graph('fortisase_private_access_packet_loss', 'Hub packet loss', 'fortisase_private_access_packet_loss')


metric_idp_devices = catalog_metric('fortisase_idp_devices', 'IDP devices', SESSION_UNIT, Color.BLUE)
metric_idp_users = catalog_metric('fortisase_idp_users', 'IDP users', SESSION_UNIT, Color.GREEN)
metric_idp_count = catalog_metric('fortisase_idp_count', 'Identity providers', SESSION_UNIT, Color.PURPLE)
metric_idp_sync_progress = catalog_metric('fortisase_idp_sync_progress', 'Synchronization progress', Unit(DecimalNotation('%')), Color.BLUE)
metric_idp_sync_age = catalog_metric('fortisase_idp_sync_age', 'Time since successful sync', DURATION_UNIT, Color.ORANGE)
graph_idp_counts = catalog_graph('fortisase_idp_counts', 'Identity provider devices and users', 'fortisase_idp_devices', 'fortisase_idp_users')
graph_idp_sync_progress = catalog_graph('fortisase_idp_sync_progress', 'Identity provider synchronization progress', 'fortisase_idp_sync_progress')
graph_idp_sync_age = catalog_graph('fortisase_idp_sync_age', 'Identity provider synchronization age', 'fortisase_idp_sync_age')
