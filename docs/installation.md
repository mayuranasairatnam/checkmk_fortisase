# Installation and configuration

[← README](../README.md) · [Installation](installation.md) · [Authentication](authentication.md) · [Monitoring](monitoring.md) · [Development](development.md)

## Requirements

- Checkmk **2.4 or 2.5**, with Python **3.11+** and `requests` in the site environment.
- A dedicated FortiCloud API user assigned a **Local** permission profile with
  **FortiSASE Read-only** access. See [authentication](authentication.md).
- HTTPS access from the Checkmk site to `customerapiauth.fortinet.com` and
  `portal.prod.fortisase.com`.

## Install the package

Download the MKP using **Download MKP** in the [README](../README.md), then upload
and enable it under **Setup → Maintenance → Extension packages**. The package ID
is `check_fortisase`. No Checkmk agent is required on the monitored system.

Alternatively, as the Checkmk site user, replace `VERSION` with the downloaded
package version:

```sh
mkp add /path/to/check_fortisase-VERSION.mkp
mkp enable check_fortisase VERSION
```

To build locally, run `python3 -B build_mkp.py` from the repository directory.
See [development](development.md) for local setup and checks.

## Configure the host and rule

1. Create one host per FortiSASE tenant and select **No IP**. The host name
   is a monitoring label; the portal address is fixed.
   Select **Configured API integrations, no Checkmk agent** as the data source.
2. In **Setup**, search for **FortiSASE** and open the integration ruleset.
   Create a new rule and restrict its **Conditions → Explicit hosts** to the
   host created above.
3. Enter **API ID** and **API password** for the dedicated FortiCloud API
   user. Use the Checkmk Password Store for the password.
4. Use a separate rule and API account for each monitored tenant. The rule
   does not require a portal URL or manually generated OAuth token.
5. Review the [connection settings](#connection-settings), then save the rule.
6. Activate changes and continue with [service discovery](#discover-and-check-services).

## Connection settings

| Setting | Default / behavior |
| --- | --- |
| Portal address | Fixed to `https://portal.prod.fortisase.com` |
| Authentication address | Fixed to `https://customerapiauth.fortinet.com` |
| Timeout per API request | 30 seconds |
| TLS certificate verification | Enabled for portal and authentication requests |

OAuth tokens are managed automatically. The rule has no portal URL or token
lifetime setting. See [authentication](authentication.md) for permissions.

## Discover and check services

Run service discovery on the host, accept the discovered services and activate
changes. Inspect **FortiSASE API** for collection errors. After changing the
monitoring scope, rescan the host and use **Remove vanished services** for items
that are no longer monitored.

Services depend on the resource sections returned by the API. A successful
empty IDP inventory creates the **FortiSASE Identity Providers** summary. An
unexpected data structure from the optional IDP endpoint skips IDP discovery
without an API warning. Existing IDP services may show missing data until removed
through service discovery. Certificate thresholds are configured with
**FortiSASE Certificate Expiry**; see [monitoring](monitoring.md) for all thresholds.

As the Checkmk site user, run discovery and check the result:

```sh
cmk -vI YOUR_HOST
cmk -nv YOUR_HOST
```

### Standalone agent check

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
