# Services, metrics and thresholds

[← README](../README.md) · [Installation](installation.md) · [Authentication](authentication.md) · [Monitoring](monitoring.md) · [Development](development.md)

Services report traffic, sessions, certificates, license seats, private-access
hub health and identity-provider status.
Traffic rates are the final reported samples, not rates derived by Checkmk.

## Monitoring scope and services

| Service | Measurements and alert levels |
| --- | --- |
| FortiSASE API | Successful resource queries, errors and collection duration; WARN for partial failure, CRIT for authentication or total collection failure |
| FortiSASE SWG &lt;location&gt; | Session count and received/sent session bytes |
| FortiSASE VPN &lt;location&gt; | Session count and received/sent session bytes |
| FortiSASE VPN/SWG Bandwidth &lt;location&gt; | Shared user-access and outbound receive/transmit rates |
| FortiSASE Private Access Bandwidth &lt;location&gt; | Private-access receive/transmit or unclassified throughput |
| FortiSASE Thin Edge Bandwidth &lt;region&gt; | Thin Edge receive/transmit or unclassified throughput |
| FortiSASE FortiExtender Bandwidth &lt;region&gt; | FortiExtender receive/transmit or unclassified throughput |
| FortiSASE FortiGate Bandwidth &lt;region&gt; | FortiGate receive/transmit or unclassified throughput |
| FortiSASE Certificate &lt;certificate&gt; | Remaining lifetime; default WARN below 30 days, CRIT below 14 days |
| FortiSASE License | Licensed, used and free seats plus utilization; WARN from 90%, CRIT from 100% |
| FortiSASE Identity Providers | Provider inventory and identity validation |
| FortiSASE IDP &lt;provider&gt; | Domain/GUID, IDP and connector status, sync errors, devices, users, progress and sync age |
| FortiSASE Private Access &lt;hub&gt; VPN Status | Configured hub tunnel status across reporting nodes |
| FortiSASE Private Access &lt;hub&gt; Link Health | Link status and maximum latency, jitter and packet loss across reporting nodes |
| FortiSASE Private Access &lt;hub&gt; BGP Status | Configured BGP neighbor state across reporting nodes |

## API health

**FortiSASE API** is discovered whenever its status section exists. It reports
successful/total unique resource groups and error count, with error details. All
successful: OK; some failed: WARN; authentication failure or all failed: CRIT.
The optional IDP query is excluded from coverage when its response has an
unexpected data structure; this case does not trigger WARN.
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
See [authentication](authentication.md#troubleshooting) for access and
failure behavior.

## Graphs

Graphing definitions cover generic and directional throughput,
session byte totals, combined user-access/outbound PoP bandwidth and all
individual metrics, including certificate lifetime and API collection duration.
License seat allocation and utilization have separate graphs.


## Private-access hub services (1.0.1)

Each configured hub produces three services:

- `FortiSASE Private Access <Hub Name> VPN Status`
- `FortiSASE Private Access <Hub Name> Link Health`
- `FortiSASE Private Access <Hub Name> BGP Status`

The item is `config.alias` from `/resource-api/v1/private-access/service-connections`.
The plugin maps each hub sequence number to its health/tunnel key as
`hub<seq_num>`; for example, `seq_num: 1` maps to `hub1`. It does not guess by
array position or match unrelated tunnels.
BGP neighbors are selected by the configured `config.bgp_peer_ip`.

`/resource-api/v1/security/sdwan/health` returns records identified by node serial
number. All reporting nodes contribute to each hub service; their identities and
states appear in the check output. A down hub tunnel/link or a known BGP state
other than Established produces CRIT, even if another node is healthy. Missing
or unrecognized states produce UNKNOWN. Missing, duplicate or malformed hub/node
identities cannot produce healthy placeholder services. Failed hub provisioning
also produces CRIT; unfinished/unrecognized provisioning states produce UNKNOWN.
Unrelated down tunnels, including `default-ipsec`, are ignored.

The plugin aggregates nodes per hub. Since 1.0.1, node labels are resolved by
joining each health record's `primaryKey` to `device_sn` from
`/resource-api/v1/admin/config?include_sites=true`. It reads `region_alias` and
`pop_airport_name` to render city/datacenter labels such as `Zurich (zrh-g2)`
and `Bangalore (blr-f1)`. The code comes from the API; for example, metadata
reporting `blr-f2` renders `Bangalore (blr-f2)` without rewriting it to `blr-f1`.
Country/provider qualifiers are removed using the existing location formatter.
Raw serial numbers remain available in service details.

Repeated site references in federated sites and configuration slaves are merged
by serial. Conflicting aliases or datacenter codes are not guessed: that node
retains its serial-number label. If a datacenter code is missing, the full region
alias is retained. Missing/denied metadata does not suppress hub monitoring;
the optional naming section falls back to serial labels and API errors remain
visible in the API service. Only serial, alias and datacenter fields are emitted;
tenant configuration, invitations and credentials are omitted.

The node metric counts received records, not expected infrastructure capacity;
a node entirely omitted by the API cannot be identified as absent.

Link measurements are the maximum valid value across reporting nodes. The
Checkmk rule **FortiSASE Private Access Link Health** configures these upper
levels; reaching a level triggers its state. These are plugin defaults, separate
from FortiSASE's configured routing SLA:

| Measurement | Unit | WARN | CRIT |
| --- | --- | ---: | ---: |
| Latency | ms | 150 | 300 |
| Jitter | ms | 30 | 50 |
| Packet loss | % | 1 | 5 |

Zero is valid; negative, non-finite or missing measurements produce UNKNOWN.
Packet loss above 100% is invalid. Valid measurements from other nodes remain
available. The maximum latency, jitter and packet-loss metrics each have a graph.

Private-access monitoring has been live-tested by the maintainer with
FortiCloud API credentials and service discovery in Checkmk. Automated regression
tests also cover the API responses and checks.
A denied new endpoint is reported by the API service without discarding existing
traffic, session, certificate or license sections.


## Identity providers (1.0.1)

`FortiSASE Identity Providers` reports the returned provider count, including a
healthy empty inventory. `FortiSASE IDP <provider>` uses the same checks and
summary rendering as FortiClient EMS. Names prefer connector alias, explicit
provider name, domain name or group path; a top-level provider ID is retained
when present. GUIDs appear in the output rather than in the service name.
Duplicate names produce UNKNOWN instead of combining unrelated providers.

The provider summary contains Domain, GUID, IDP online/offline, Connector
online/offline, synchronization errors, Devices, Users, Sync progress,
Last successful sync and Sync age. For example, a last successful sync about
25 minutes ago is rendered as `Sync age: 0.4 hours`.

Provider/connector offline states and synchronization errors default to CRIT.
The **FortiSASE identity providers** rule allows WARN instead, independently
for each condition. Time since `status.last_success_enumerated` defaults to
WARN at 86400 seconds (24 hours), CRIT at 172800 seconds (48 hours). These
limits are configurable; the displayed age is in hours. Timestamps without a
UTC offset are interpreted as UTC, matching EMS. Invalid, missing or future
successful-sync timestamps produce UNKNOWN and no fabricated sync-age metric.
Missing availability flags, invalid counters and progress outside 0–100% also
produce UNKNOWN. Zero devices/users and zero sync progress are valid values.

| Metric | Unit |
| --- | --- |
| `fortisase_idp_count` | Provider count |
| `fortisase_idp_devices` | Device count |
| `fortisase_idp_users` | User count |
| `fortisase_idp_sync_progress` | % |
| `fortisase_idp_sync_age` | Seconds |

Graphs show devices/users, progress and synchronization age. The collector uses
the existing FortiCloud OAuth credentials and validates `result.retval == 1`.
Only monitoring fields are exported; connector login/host settings are omitted.
If the IDP endpoint reports `API response has an unexpected data structure`,
the collector skips the optional IDP section and excludes that query from API
coverage. No IDP services are discovered and API health does not warn for this
case, which can occur when no identity provider is configured.
Existing IDP services receive no section in this case and may appear as missing
data until removed through service discovery.
A denied IDP request is reported through API health without discarding other
services. Identity-provider monitoring has been live-tested by the maintainer
with FortiCloud API credentials and service discovery in Checkmk. Automated
regression tests also cover the API responses and checks.
