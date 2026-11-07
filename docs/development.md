# Development

The repository follows the FortiAnalyzer/FortiManager package structure.

```text
cmk_addons_plugins/fortisase/
  agent_based/          fortisase_api.py, fortisase_swg.py, fortisase_vpn.py,
                        fortisase_bandwidth.py, fortisase_pop.py,
                        fortisase_certificates.py, fortisase_license.py (API v2)
  lib/common.py         Shared models, JSON/number validation, domain parsers
                        and SWG/VPN session evaluation
  libexec/agent_fortisase
  rulesets/            Datasource and certificate threshold forms (API v1)
  server_side_calls/   fortisase.py: command construction with a Secret reference (API v1)
  graphing/            fortisase.py: metric catalog and chart constructors (API v1)
cmk_addons/plugins -> ../cmk_addons_plugins
docs/                  Installation, authentication, monitoring, development
tests/                 Offline transport, checks and packaging tests
build_mkp.py           Reproducible native MKP builder
.github/               CI and automatic release version selection
```

## Data flow

The datasource rule supplies credentials, request timeout and TLS verification settings.
The rule does not expose portal URL or OAuth fallback lifetime overrides. Server-side
calls keep the Checkmk Secret object intact. The special agent resolves it,
locks its credential cache, authenticates and collects ten unique resource groups covering traffic, sessions, remote
certificates and license seat allocation.
Successful JSON responses are emitted into the resource sections and the
`fortisase_api` status section. Agent-based parsers validate responses once into typed dataclass records.
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
anonymous identities and prevents non-finite aggregates from becoming metrics. The MKP includes the `cmk_addons_plugins` source tree only.

Function docstrings follow the FortiAnalyzer convention: a description followed
by **Input** and **Output**. Preserve established service, section and metric IDs;
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
credentials or network calls are needed. The plugin has also been actively tested
against a live FortiSASE tenant. Offline tests do not establish real Checkmk
loader/form compatibility or tenant behavior. When validating changes, test
installation, forms, activation, discovery and service output in a real site,
including an empty tenant and a failed endpoint.

## Packaging and releases

`build_mkp.py` creates `check_fortisase-1.0.2.mkp` by default. It accepts
`--version MAJOR.MINOR.PATCH`. Metadata targets Checkmk 2.4.0 through 2.5.99;
this defines the supported Checkmk version range.
The archive contains `info`, `info.json` and `cmk_addons_plugins.tar`. File
ordering, timestamps, ownership and compression metadata are deterministic;
libexec members are executable. Generated MKPs and Python caches are ignored.

GitHub Actions tests and builds on pull requests and pushes to `main`. After a
successful push to `main`, the release job selects the current stable tag or the
next patch version and publishes a GitHub release containing the MKP. It starts
at 1.0.0 if no stable release tags exist. Re-running an already tagged commit
reuses its version. The first published release is 1.0.0; the earlier locally built development
packages are not the public release history. No publishing happens merely by
running local tests/builds.

## Implementation boundaries

The runtime implementation uses its own typed normalization, indexed discovery,
shared session evaluation, paired traffic registrations and graphing catalog.
Comments and callback documentation describe these models in the Input/Output
format used by the FortiAnalyzer template. Graph declarations use common unit
and constructor definitions rather than duplicating metric construction blocks.

API endpoint names and payload fields are external contracts. Checkmk callback
argument names, registration prefixes and persisted service/metric identifiers
also constrain the source text. Preserve these identifiers when changing the
implementation.

## API contracts

Endpoint paths, OAuth client ID/grants and response-field mappings define the
FortiSASE API integration. Build layout, release
workflow and documentation organization follow `check_fortianalyzer` and
`check_fortimanager`. The new package is self-contained and does not need these
sibling directories at runtime or in CI.

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
