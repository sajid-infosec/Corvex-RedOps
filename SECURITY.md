# Security Policy

## Authorized Use Only
PentestIQ is an offensive security tool that performs active testing and
exploitation. Use it **only** against systems you own or are explicitly,
verifiably authorized to test. Unauthorized use may be illegal. See
`docs/LEGAL_AND_ETHICS.md`.

## Reporting a Vulnerability in PentestIQ
If you discover a security issue in PentestIQ itself, please report it
privately to the maintainer rather than opening a public issue. A dedicated
security contact and disclosure window will be published before public
release.

## Handling of Engagement Data
Scan results, credentials, and findings are sensitive. PentestIQ stores
engagement data locally by default and excludes it from version control
(see `.gitignore`). Never commit real engagement data to any repository.
