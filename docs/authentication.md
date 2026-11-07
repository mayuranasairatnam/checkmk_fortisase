# Authentication and API access

Use a dedicated FortiCloud API ID and password authorized for the tenant's
FortiSASE resources. This plugin uses OAuth
password/refresh grants with `client_id=FortiSASE`. It does not use a static
FortiGate-style API token. Tenant permissions and response formats need to be
verified with the actual deployment.

Checkmk passes a `Secret` object as the argument for `--api-password-id`. At
runtime the framework supplies a password-store reference (`ID:/absolute/file`),
which the agent resolves through `cmk.utils.password_store.lookup`. The actual
password is never expanded into argv. Stdin is available for standalone tests.

## Token lifecycle

1. Reuse a cached access token while its calculated expiry remains valid.
2. Refresh expired/about-to-expire tokens using the cached refresh token.
3. Fall back to a password grant if refresh fails or no refresh token exists.
4. On a portal HTTP 401, remove the cache, perform a password grant and retry once.

`expires_in` determines the lifetime; the internal fallback is 3000 seconds.
The portal URL and fallback lifetime are not exposed in the integration rule. The agent
subtracts 60 seconds before caching. If a refresh response omits a new refresh
token, the prior one is retained.

Tokens are stored under `$OMD_ROOT/tmp/fortisase/` or, for standalone runs,
`<system-temp>/fortisase-<uid>/`. The directory is mode 0700. Cache files use mode
0600 and atomic replacement. Cache identity includes API ID, portal origin and
password, hashed into a filename. A per-identity lock serializes complete
collections within the same cache directory to prevent refresh races. Different
sites do not share this lock. Use dedicated credentials per independent poller.

TLS verification is enabled for both auth and portal calls. Redirects are not
followed. Debug output and API errors include no response bodies, passwords or
tokens. The JSON agent output contains the collected resource data and should be
treated as private monitoring data.

## Endpoints

| Request | Endpoint | Purpose |
| --- | --- | --- |
| POST | `https://customerapiauth.fortinet.com/api/v1/oauth/token/` | Password and refresh grants |
| GET | `/monitor-api/v1/traffic-history?type=<type>` | Traffic history for six types |
| GET | `/monitor-api/v1/user/swg/sessions` | Regional SWG sessions |
| GET | `/monitor-api/v1/user/vpn/sessions` | Regional VPN sessions |
| GET | `/resource-api/v2/system/certificate/remote-certificates` | Remote certificate metadata |
| GET | `/endpoint/fct/api/public/v1/sase_to_ems/cloud/fortiguard_cloud_vpn/get_seats` | Licensed and used endpoint seats |

Traffic types: `InboundUser`, `PrivateAccess`, `InboundThinEdge`, `FortiExtender`,
`Outbound`, `FortiGate`. Each traffic type is queried once per collection.
A normal collection queries ten unique portal resource groups plus any required
OAuth call. Session counts cover records returned by their respective session
endpoints. The plugin does not collect VPN SSO configuration, endpoint
inventories or ZTNA access-key metadata. The license query returns seat counts
only and does not require endpoint inventory collection.

## Failure behavior

An endpoint failure leaves other successfully collected sections available.
**FortiSASE API** reports WARN for partial failure and CRIT for failed
authentication or no successful endpoints. Error details identify endpoint/type
and a sanitized failure class or HTTP status. Application-level errors and
unexpected response envelopes count as failures.

The agent returns exit status 0 when it has emitted API collection status,
including API failures. Initialization failures (such as a missing password-store
entry or unwritable cache) produce a sanitized stderr message and exit status 1.
Previously discovered services whose section is absent are handled as missing
data by Checkmk. New per-item services require successful resource data.

## License seat endpoint

The seat endpoint uses the same OAuth access token as the other queries. No
browser cookies or copied portal tokens are stored in the plugin. The
response uses `result.retval: 1` for success and a `data` object with
integer `seats` and `used` values. The client validates this envelope separately
from the Resource API list responses. Agent output contains only these counts
and the success indicator.

The maintainer has verified license seat monitoring with a dedicated FortiCloud
API account in a live Checkmk environment. If an API request is denied,
**FortiSASE API** reports the failed query and other successful services remain
available. A new license service requires a successful seat response; an existing
one reports missing data when its section is unavailable.
