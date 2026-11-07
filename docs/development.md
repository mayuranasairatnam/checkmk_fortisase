# Development, tests and releases

[← README](../README.md) · [Installation](installation.md) · [Authentication](authentication.md) · [Monitoring](monitoring.md) · [Development](development.md)

## Source layout, tests and reproducible package build

Sources live under `cmk_addons_plugins/fortisase/`. The local import symlink
`cmk_addons/plugins` points to `../cmk_addons_plugins` and is excluded from the
package.

| File | Purpose |
| --- | --- |
| `libexec/agent_fortisase` | FortiCloud OAuth, API collection and agent section output |
| `server_side_calls/fortisase.py` | Builds the special-agent command with a password-store reference |
| `rulesets/special_agent.py` | Credentials, request timeout and TLS verification in Setup |
| `rulesets/check_parameters.py` | Certificate, private-access and identity-provider alert settings |
| `graphing/fortisase.py` | Metric definitions and graphs |
| `agent_based/fortisase_api.py` | API collection status |
| `agent_based/fortisase_swg.py` / `fortisase_vpn.py` | Regional session counts and byte totals |
| `agent_based/fortisase_pop.py` | Shared user-access and outbound bandwidth |
| `agent_based/fortisase_bandwidth.py` | Private-access, Thin Edge, FortiExtender and FortiGate bandwidth |
| `agent_based/fortisase_certificates.py` | Remote certificate expiry |
| `agent_based/fortisase_license.py` | License seat allocation and utilization |
| `agent_based/fortisase_private_access.py` | Hub VPN, BGP and link health |
| `agent_based/fortisase_idp.py` | Identity-provider inventory and synchronization health |
| `lib/common.py` | Shared validation, models, location formatting and session evaluation |
| `tests/` | Offline transport, check, release and packaging tests |
| `build_mkp.py` | Reproducible native MKP build |
| `.github/` | CI checks and automatic releases |

## Data flow

The datasource rule supplies credentials, request timeout and TLS verification settings.
The rule does not expose portal URL or OAuth fallback lifetime overrides. Server-side
calls keep the Checkmk Secret object intact. The special agent resolves it,
locks its credential cache, authenticates and collects fourteen unique resource groups covering traffic, sessions, remote
certificates, license seats, private-access hubs, identity providers and node
location metadata. These fourteen groups include six traffic types; skipping an
unsupported IDP response reduces the reported total to thirteen.
Successful JSON responses are emitted into the resource sections and the
`fortisase_api` status section. Agent-based parsers validate responses into typed records or indexed dictionaries.
Discovery and checks use indexed regional measurements rather than traversing raw
JSON again. A shared traffic model serves device/private-access bandwidth and PoP checks. SWG and VPN
have separate registration modules and callbacks; shared session evaluation lives
in `lib/common.py`. The session plugins subscribe only to their protocol-specific
inventory; the PoP plugin owns the shared user-access and outbound sections. Both shared
and private-access bandwidth plugins additionally consume session inventories
only to associate readable locations with reported datacenter IDs. Bandwidth checks consume rates in bits per second; SWG/VPN checks retain their
session byte totals.
Certificates retain expiry timestamps and evaluate lifetime at check time.
The license parser validates the seat endpoint's distinct result envelope and
non-negative integer counts. License output is restricted to seat capacity,
usage and the success indicator. No browser-session credentials are embedded.
Validation keeps valid zeroes distinct from missing values, rejects duplicate or
anonymous identities and prevents non-finite aggregates from becoming metrics. The MKP includes the `cmk_addons_plugins` source tree and a copy of the license.

Function docstrings contain a description followed by **Input** and **Output**.
Preserve established service, section and metric IDs;
keep shared models, normalization and session evaluation in `lib/common.py`,
the only module under `lib/`. Changes to parsing should be tested across the real
JSON → typed section → discovery/check boundary.

## Local checks

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install 'requests>=2.31,<3'
python3 -B -m unittest discover -s tests -v
python3 -B build_mkp.py
```

Tests use mocked HTTP responses and small Checkmk API doubles when Checkmk is
unavailable. They cover OAuth grants/cache/401 retry, secret transport, partial
failures, traffic aggregation and zero values, session joins, certificate expiry,
registration relationships, duplicate/anonymous identities, missing counters,
malformed final samples, aggregate overflow, check-time certificate lifetime,
version selection, license seat allocation and deterministic packaging. No
credentials or network calls are needed. All monitoring features, including
private-access hubs and identity providers, have also been live-tested by the maintainer against a FortiSASE tenant in
Checkmk, including service discovery. Offline tests do not establish real Checkmk
loader/form compatibility or tenant behavior. When validating changes, test
installation, forms, activation, discovery and service output in a real site,
including an empty tenant and a failed endpoint.

## CI and releases

`build_mkp.py` creates `check_fortisase-1.0.1.mkp` by default. It accepts
`--version MAJOR.MINOR.PATCH`. Metadata targets Checkmk 2.4.0 through 2.5.99;
this defines the supported Checkmk version range.
The archive contains `info`, `info.json` and `cmk_addons_plugins.tar`. File
ordering, timestamps, ownership and compression metadata are deterministic;
libexec members are executable. Generated MKPs and Python caches are ignored.

GitHub Actions tests and builds on pull requests and pushes to `main`. After a
successful push to `main`, the release job selects the current stable tag or the
next patch version and publishes a GitHub release containing the MKP. It starts
at 1.0.0 if no stable release tags exist. Re-running an already tagged commit
reuses its version. The explicit build version controls local packaging; GitHub
release versions are selected from Git tags, independently of the default in
`build_mkp.py`. No publishing happens merely by running local tests/builds.

## Implementation boundaries

The runtime implementation uses its own typed normalization, indexed discovery,
shared session evaluation, paired traffic registrations and graphing catalog.
Comments and callback documentation describe these models using the Input/Output
format. Graph declarations use common unit
and constructor definitions rather than duplicating metric construction blocks.

API endpoint names and payload fields are external contracts. Checkmk callback
argument names, registration prefixes and persisted service/metric identifiers
also constrain the source text. Preserve these identifiers when changing the
implementation.

## API contracts

Endpoint paths, OAuth client ID/grants and response-field mappings define the
FortiSASE API integration. The package is self-contained at runtime and in CI.

## License validation

The license-seat parser and transport validate the `result.retval`/`data`
response. Tests cover threshold boundaries, zero and exceeded capacity, invalid
counts, application failures and denied access without losing other sections.
The maintainer has also live-tested OAuth access with FortiCloud API credentials
and the license service in Checkmk. No browser session credentials are embedded in tests
or source. VPN SSO, endpoint inventory and ZTNA services and their API queries
are not included in the package.

## Lint checks

The CI workflow defines Ruff and yamllint versions and rules directly in
`.github/workflows/ci.yml`. To repeat these checks locally, install the
listed tools and run the commands from the corresponding workflow steps.
Ruff includes extensionless `libexec/agent_*` scripts.
