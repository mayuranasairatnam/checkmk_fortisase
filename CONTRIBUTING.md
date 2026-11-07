# Contributing

Bug reports, documentation corrections and focused pull requests are welcome.
Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

For bugs, include plugin, Checkmk and FortiSASE versions, reproduction steps and
expected/actual behavior. Sanitize API samples: remove credentials, tokens,
session/user details and tenant identifiers before sharing.

Start with the [README](README.md) and [development guide](docs/development.md).
Run the offline tests and MKP build before submitting code changes. State which
real-site checks you performed and which remain unverified.

Preserve service names and exported IDs where possible. Retain valid zero
measurements, handle missing data explicitly and keep credentials out of argv,
logs, exceptions and service output. Follow the existing multiline Input/Output
docstring style. Update the relevant guide when configuration or behavior changes.

Sources live under `cmk_addons_plugins/fortisase`; `cmk_addons/plugins` is a local
import symlink. Generated MKPs and Python caches must not be committed. CI manages
release versions and tags after changes reach `main`.

Contributions are licensed under GPL-2.0-or-later. Preserve applicable notices and
identify third-party code and its license. AI-assisted contributions are welcome;
review and verify the changes and disclose substantial AI assistance in the pull
request description.
