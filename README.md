# API-based Checkmk Plugin for FortiSASE

[<img src="docs/assets/octicons/download-16.svg" width="16" height="16" alt=""> Download MKP](https://github.com/mayuranasairatnam/checkmk_fortisase/releases/latest) · [<img src="docs/assets/octicons/book-16.svg" width="16" height="16" alt=""> Installation](#installation)

[<img src="docs/assets/octicons/bug-16.svg" width="16" height="16" alt=""> Report a Bug](https://github.com/mayuranasairatnam/checkmk_fortisase/issues/new?title=Bug%3A%20) · [<img src="docs/assets/octicons/light-bulb-16.svg" width="16" height="16" alt=""> Request a Feature](https://github.com/mayuranasairatnam/checkmk_fortisase/issues/new?title=Feature%3A%20) · [<img src="docs/assets/octicons/git-pull-request-16.svg" width="16" height="16" alt=""> Contribute](CONTRIBUTING.md)

---

Author: **Mayuran Asairatnam** · Package: **check_fortisase**

Monitor FortiSASE through a native Checkmk special agent using FortiCloud OAuth.
No agent needs to be installed on an appliance.

## Monitoring scope

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

Location names use `city (datacenter)` when the API provides both identifiers.
For example: `FortiSASE SWG Zurich (zrh-g2)`. The SSO certificate appears as
`FortiSASE Certificate (Microsoft Azure Federated SSO Certificate)` when that
certificate is returned.

InboundUser and Outbound rates are collected once per location in the VPN/SWG
bandwidth service. SWG and VPN services retain their own session measurements.
Only remote certificates are collected.

See the [monitoring reference](docs/monitoring.md) for metrics, graphs and alert behavior.

## Installation

1. Build with `python3 -B build_mkp.py`, or download an available release MKP.
2. Install and enable the package in **Setup → Maintenance → Extension packages**.
3. Create one host per tenant with **No IP** and **Configured API integrations, no Checkmk agent**.
4. Add a **FortiSASE** integration rule with the dedicated FortiCloud API ID and password.
5. Activate changes, discover services and accept them.

TLS verification is enabled. Credentials resolve through the Checkmk Password
Store; passwords and OAuth tokens are not put into process arguments.
See [installation](docs/installation.md) for commands and migration details.

## Compatibility and validation

Supports Checkmk **2.4 and 2.5**. Python **3.11+** and `requests` are required.
All monitoring functions, including license seat monitoring with FortiCloud API
credentials, have been live-tested by the maintainer against a FortiSASE tenant
in Checkmk. Automated tests cover transport, token lifecycle, session and
bandwidth checks, certificate expiry, license seat allocation and reproducible
packaging.

## Tested environments

| Component | Tested versions |
| --- | --- |
| FortiSASE | 26.3.2 |
| Checkmk | 2.4, 2.5 |

## Documentation

| Guide | Contents |
| --- | --- |
| [Installation](docs/installation.md) | Host setup, settings, CLI and migration |
| [Authentication and API access](docs/authentication.md) | Credentials, OAuth cache, endpoints and errors |
| [Monitoring reference](docs/monitoring.md) | Services, metrics, units, thresholds and graphs |
| [Development](docs/development.md) | Layout, tests, builds, CI and release workflow |

## Contributing and license

Independent community plugin. Not affiliated with or endorsed by Fortinet.

See the [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).
Licensed under [GPL-2.0-or-later](LICENSE). Copyright (C) 2026 Mayuran Asairatnam.

Icons: [GitHub Octicons](https://github.com/primer/octicons), licensed under [MIT](docs/assets/octicons/LICENSE).
