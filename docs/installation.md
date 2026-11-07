# Installation

## Requirements

- Checkmk 2.4 or 2.5, with Python 3.11+ and `requests` in the site environment.
- A dedicated FortiCloud API account with access to the tenant's FortiSASE resources.
- HTTPS access to `customerapiauth.fortinet.com` and the configured FortiSASE portal.

## Build and install

From the repository directory:

```sh
python3 -B build_mkp.py
```

Upload `check_fortisase-1.0.2.mkp` under **Setup → Maintenance → Extension packages**
and enable it. Alternatively, as the Checkmk site user:

```sh
mkp add /path/to/check_fortisase-1.0.2.mkp
mkp enable check_fortisase 1.0.2
```

For development, copy `cmk_addons_plugins/fortisase` into
`~/local/lib/python3/cmk_addons_plugins/fortisase` and retain executable permissions
on `libexec/agent_fortisase`. Use either manual installation or the MKP to avoid
mixing managed and unmanaged files.

## Configure the host and rule

Create one host per FortiSASE tenant. Select **No IP** and
**Configured API integrations, no Checkmk agent**. The host name is a monitoring
label; the agent connects to `https://portal.prod.fortisase.com`.

Find **FortiSASE** in Setup's integration rules. Enter the **API ID** and **API password**, preferably from the password
store. Restrict the rule to the intended host.

| Setting | Default | Meaning |
| --- | --- | --- |
| Timeout | 30 seconds | Per HTTP request |
| TLS verification | Verify | Applies to portal and OAuth requests |

The portal URL is fixed to `https://portal.prod.fortisase.com`. OAuth uses the
reported `expires_in`, with an internal fallback of 3000 seconds. These are not
configuration fields. Saved overrides for these removed fields are discarded
when migrating a rule and ignored when constructing the agent command.

Activate changes, run service discovery and accept the services. An empty tenant
may only yield the API service. Inspect **FortiSASE API** for collection errors.
Certificate thresholds are configured with **FortiSASE Certificate Expiry**.

## Manual agent check

Run as the site user. The following prompts for a password without echoing it:

```sh
read -r -s -p 'API password: ' SASE_PASSWORD
printf '\n'
printf '%s\n' "$SASE_PASSWORD" | \
  ~/local/lib/python3/cmk_addons_plugins/fortisase/libexec/agent_fortisase \
  --api-id YOUR_API_ID --password-from-stdin --debug
unset SASE_PASSWORD
```

The prompt example uses Bash. `--debug` logs request paths and HTTP status codes
to stderr. Stdout contains Checkmk sections and can include session/user data;
keep captures private and sanitize them before sharing.

For site validation:

```sh
cmk -d YOUR_HOST
cmk -IIv YOUR_HOST
cmk -nv YOUR_HOST
```

## Updating the package

Back up your rules before updating. Keep only one package version active to
avoid duplicate integration and check registrations.

For retained services, the integration name, API ID/password keys, section names,
check IDs, metric names and certificate ruleset name are preserved. Service name
changes are described below.
See below for removal of the standalone Last RxTx services. Saved timeout values are converted to integer seconds by the server-side call.
Former `base_url` and `cache_ttl` overrides are removed during rule migration;
the integration uses the built-in portal and token fallback defaults.
Missing or malformed measurements now produce explicit validation errors instead
of implicit zero values. Anonymous records no longer create `unknown` or
positional placeholder items; remove any such vanished services after reviewing
the source data. Resave the rule, activate changes and rediscover services. The additional
**FortiSASE API** service must be accepted. Legacy command-line options for
plaintext passwords and password files are replaced by a Checkmk password-store
reference or stdin.

OAuth cache filenames have changed. The first run creates a new cache and may
perform a password grant. Stop the old poller first to avoid competing token
lifecycles. Credential reuse across independent sites/pollers is not coordinated.

## Removed Last RxTx services

The standalone byte-sample plugin and its **Last RxTx** services have been removed.
After upgrading, activate changes and use service discovery's **Remove vanished
services** action to remove previously accepted Last RxTx services. Bandwidth
services and received/sent byte totals inside SWG/VPN services remain available.

## Initial public release and local development packages

The first public release is **1.0.0**. Earlier locally built 1.0.1–1.0.4 archives
were development packages; they do not define the GitHub release sequence. If you
installed one of those packages, disable it before enabling the public 1.0.0
release. Keep only one active `check_fortisase` version to avoid overlapping
registrations. A version-number change does not remove existing monitored
services or update rules that match full service names.

## Service discovery after migration

The public release includes the API success-case crash fix and uses descriptive
service names with city and datacenter IDs from the API:

- `FortiSASE Private Access Bandwidth Doha (doh-g2)`
- `FortiSASE VPN/SWG Bandwidth Zurich (zrh-g2)`
- `FortiSASE VPN Doha (doh-g2)`
- `FortiSASE SWG Zurich (zrh-g2)`

VPN and SWG services report their own session counts and session byte
totals. Shared user-access/outbound rates are collected once per location in the
VPN/SWG Bandwidth service. Private Access Bandwidth measures a separate traffic
type. If datacenter metadata is unavailable, bandwidth names retain the API's
full location label rather than inventing an identifier.

After installation, rescan services, remove vanished old names, accept the new
services and activate changes. Review rules matching full service names;
historical graphs under earlier names are not transferred automatically.
Previously accepted raw region-key session services remain checkable until the
discovery rename has been reviewed. Standalone Last RxTx services remain removed.

## License service and migration from local development packages

The package monitors traffic, sessions, remote certificates and seats through the
**FortiSASE License** seat service. The VPN SSO, endpoint inventory, individual
endpoint and ZTNA access-key services introduced in the local 1.0.6 package
are removed, together with their API queries and graph definitions.

After updating, activate changes and rediscover services. Remove vanished
**FortiSASE VPN SSO**, **FortiSASE Endpoints**, **FortiSASE Endpoint <device ID>**
and **FortiSASE ZTNA Access Keys** services if they were accepted in 1.0.6.
Accept **FortiSASE License** if it is newly discovered, then activate changes.
The certificate and SWG naming changes remain in place.

The license service queries the EMS-backed seat endpoint with the existing
OAuth token. This authentication method and the license service have been
live-tested by the maintainer. A denied query appears in **FortiSASE API** while
other successful resources remain available. See [monitoring](monitoring.md)
for seat calculations and alert levels.

## Certificate and SWG service names

Certificate services now use `FortiSASE Certificate` instead of `Cert`.
For example, `Cert FortiSASE (Microsoft Azure Federated SSO Certificate)` becomes
`FortiSASE Certificate (Microsoft Azure Federated SSO Certificate)`.
Session services use `FortiSASE SWG` instead of `FortiSASE Web Gateway`.

After updating the package, rediscover services, remove the vanished names,
accept the renamed services and activate changes. Review rules matching full
service names. Historical graphs under the old names are not transferred
automatically. Section names, check IDs, metric names and certificate thresholds
are unchanged. Previously discovered certificate items remain checkable until
rediscovery.
