# Monitoring reference

The initial public release uses descriptive service names and retains established
metric identifiers from the local development packages.
Traffic rates are the final reported samples, not rates derived by Checkmk.

## API health

**FortiSASE API** is discovered whenever its status section exists. It reports
successful/total unique resource groups and error count, with error details. All
successful: OK; some failed: WARN; authentication failure or all failed: CRIT.
`fortisase_api_duration` measures collection time in seconds, excluding waiting
for the local collection lock.

## Sessions

**FortiSASE SWG &lt;city&gt; (&lt;datacenter&gt;)** and
**FortiSASE VPN &lt;city&gt; (&lt;datacenter&gt;)** are discovered from `data` region
entries. Names use `regionLabel` for the city and `region` for the datacenter.
Examples: `FortiSASE VPN Doha (doh-g2)` and
`FortiSASE SWG Zurich (zrh-g2)`. If only one identifier is available, it
is retained without guessing a city or duplicating the same label. Missing identifiers do
not create placeholder services; duplicate identifiers produce validation errors.
The summary displays active-session count and the readable location. Session byte
totals appear in details and graphs. These services consume only their respective
session inventories; shared bandwidth belongs to the separate PoP service.

| Metric | Unit | Calculation |
| --- | --- | --- |
| `fortisase_sessions` | Count | Number of returned session records in the region |
| `fortisase_received_total` | Bytes | Sum of `receivedBytes` across returned sessions |
| `fortisase_sent_total` | Bytes | Sum of `sentBytes` across returned sessions |

Empty session lists report zero. A missing session list, malformed session record
or missing/invalid byte counter produces UNKNOWN. Valid independent measurements
remain available: for example, a missing receive counter suppresses only received
bytes while preserving the session count and valid sent bytes. Session byte totals reflect the returned active
sessions and are not lifetime interface counters. No session alert levels are
configured by default.

## PoP bandwidth

**FortiSASE VPN/SWG Bandwidth &lt;city&gt; (&lt;datacenter&gt;)** monitors the shared traffic at each
point of presence. Locations come from the union of InboundUser and Outbound
traffic datasets; each location is discovered once even when both sources report
it. City and datacenter names are joined through the VPN and SWG
inventories (`regionLabel` to `region`). Examples:

- `FortiSASE VPN/SWG Bandwidth Doha (doh-g2)`
- `FortiSASE VPN/SWG Bandwidth Zurich (zrh-g2)`
- `FortiSASE Private Access Bandwidth Doha (doh-g2)`
- `FortiSASE Private Access Bandwidth Zurich (zrh-g2)`

Country/provider qualifiers are omitted when a datacenter ID is known. If the
metadata is unavailable, the original complete traffic label is retained without
inventing an ID. Multiple matching datacenter IDs are listed together on one
regional service; the shared bandwidth is not duplicated. Empty session lists
still provide location metadata, so active sessions are not required.

| Metric | Unit | Source |
| --- | --- | --- |
| `fortisase_inbounduser_bps_rx` / `_tx` | bit/s | User-access receive/transmit rates |
| `fortisase_outbound_bps_rx` / `_tx` | bit/s | Outbound receive/transmit rates |
| `fortisase_inbounduser_bps` | bit/s | Non-directional user-access rate, if reported |
| `fortisase_outbound_bps` | bit/s | Non-directional outbound rate, if reported |

The summary groups rates under **User access** and **Outbound**. The same
measurements are no longer exported by VPN and SWG services. These API
traffic types do not provide a separate attribution to VPN versus SWG sessions;
nonzero PoP bandwidth can therefore coexist with empty session inventories.
Receive/transmit follow the API direction convention rather than an assumed
end-user upload/download direction. User-access and outbound rates are displayed
independently and are not added into a potentially double-counted total.

Missing data for either source produces UNKNOWN while retaining valid metrics
from the other source. Zero is a valid rate. No alert levels are enabled by
default. No additional API requests are needed for PoP monitoring.

## Throughput

Private Access names also use **&lt;city&gt; (&lt;datacenter&gt;)**. Other standalone
**FortiSASE &lt;type&gt; Bandwidth &lt;region&gt;** services exist for Private Access,
Thin Edge, FortiExtender and FortiGate. Dataset labels are interpreted as
`<direction>:<region>:<type>`. Final `bps` values are summed by region/direction.
Unclassified labels provide a generic throughput value.

| Metric | Unit |
| --- | --- |
| `fortisase_bps_rx` / `fortisase_bps_tx` | bit/s |
| `fortisase_bps` | bit/s, for unclassified-only throughput |

No alert thresholds are configured for throughput services.

Zero values are retained. Invalid, negative and non-finite traffic samples produce
validation diagnostics. Aggregates that overflow the finite numeric range are
suppressed. A malformed final sample does not fall back to older history. Missing
item data produces UNKNOWN for existing items. Datasets without identifiers do
not create positional or anonymous services. Throughput is
stored in bit/s; the Checkmk bandwidth renderer receives bytes/s (`bps / 8`).

## Remote certificates

**FortiSASE Certificate &lt;name&gt;** uses `$meta.info.name`, `primaryKey`, or subject CN as identity.
If name and CN differ, the item is `name (CN)`. When the certificate name is
`FortiSASE`, the item is `(CN)` to avoid repeating the product name. For example:
`FortiSASE Certificate (Microsoft Azure Federated SSO Certificate)`. Renaming the
certificate name or CN may require service rediscovery. Only `/resource-api/v2/system/certificate/remote-certificates`
is queried; local certificates are outside this plugin's current scope.

Remaining days = (`validTo` timestamp − current UTC time) / 86400. ISO8601 offsets
and `Z` are supported; timestamps without a timezone are interpreted as UTC.
Missing or invalid expiry produces UNKNOWN. Remaining lifetime is calculated at
check time, so reusing parsed data does not freeze the reported days. Duplicate
certificate identities produce UNKNOWN; certificates without any identifier do
not create placeholder services.

`fortisase_cert_days_remaining` is measured in days. Configure lower levels under
**FortiSASE Certificate Expiry**: WARN below 30 days and CRIT below 14 days by
default, including expired certificates. Levels can be disabled in the rule.

## License seats

**FortiSASE License** monitors the EMS-backed seat allocation returned by
`/endpoint/fct/api/public/v1/sase_to_ems/cloud/fortiguard_cloud_vpn/get_seats`.
It is discovered when the seat section is returned. A successful response must
contain `result.retval: 1` and non-negative integer `data.seats` and `data.used`
counts. Missing or invalid data produces UNKNOWN without zero substitutes.

| Metric | Unit | Calculation |
| --- | --- | --- |
| `fortisase_license_seats` | Count | Licensed seat capacity |
| `fortisase_license_used` | Count | Used seats |
| `fortisase_license_free` | Count | `max(0, seats - used)` |
| `fortisase_license_usage` | Percent | `used / seats * 100`, only for positive capacity |

Utilization is OK below 90%, WARN from 90% and CRIT from 100%, including
allocation beyond the licensed capacity. For zero licensed seats, zero use
reports WARN and positive use reports CRIT; no utilization percentage is emitted.
These levels are fixed in this version. License expiry is not supplied by this
endpoint and is not inferred.

For example, a response with `seats: 50` and `used: 1` reports **50 seats, 1 used,
49 free, 2.0% utilization**. The maintainer has live-tested this service with
the collector's FortiCloud OAuth credentials in Checkmk.
See [authentication](authentication.md#license-seat-endpoint) for access and
failure behavior.

## Graphs

Graphing definitions cover generic and directional throughput,
session byte totals, combined user-access/outbound PoP bandwidth and all
individual metrics, including certificate lifetime and API collection duration.
License seat allocation and utilization have separate graphs.
