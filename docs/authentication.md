# Authentication and API access

[← README](../README.md) · [Installation](installation.md) · [Authentication](authentication.md) · [Monitoring](monitoring.md) · [Development](development.md)

## Required account and permissions

1. Sign in to **FortiCloud Identity & Access Management (IAM)** with an IAM
   administrator account.
2. Create a resource-based permission profile of type **Local** that grants
   access to the **FortiSASE portal** with **Read-only** permission for the tenant
   you want to monitor.
3. Create a dedicated **API user**, assign this permission profile and download
   the API credentials.

See Fortinet's guides for [creating a permission profile](https://docs.fortinet.com/document/forticloud/latest/identity-access-management-iam/836213/creating-a-permission-profile)
and [adding an API user](https://docs.fortinet.com/document/forticloud/latest/identity-access-management-iam/282341/adding-an-api-user).

Enter this user's **API ID** and **API password** in the Checkmk **FortiSASE**
integration rule. Store the password in the Checkmk Password Store.

## Connection and authentication

The Checkmk site needs HTTPS access to:

- `customerapiauth.fortinet.com` for authentication.
- `portal.prod.fortisase.com` for monitoring queries.

The plugin obtains and refreshes OAuth tokens automatically using the API ID and
password. No manually generated token or browser cookie is required. TLS
certificate verification is enabled by default.

## Troubleshooting

Check the **FortiSASE API** service for authentication and access errors:

- **HTTP 401:** Check the API ID and password.
- **HTTP 403:** Check the API user's assigned Local permission profile, tenant
  access and FortiSASE Read-only permission.

Failed authentication or failure of all queries produces CRIT. Partial query
failures produce WARN while other successful monitoring data remains available. An unexpected data
structure from the optional identity-provider endpoint is skipped without an API
warning.

See [installation](installation.md) for setup and a manual connection check, and
[monitoring](monitoring.md) for the available services.
