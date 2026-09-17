# Third-Party Notices

> **Why this file exists (compliance, not marketing).**
> Corvex-RedOps **orchestrates** external open-source scanners rather than embedding
> them — each is invoked only when already present on the host (auto-detected;
> absent tools are skipped and never fatal). Several of those tools carry
> redistribution or copyleft terms that legally require attribution the moment
> there is a bundled image or a paid tier. This file keeps that attribution in the
> conventional location so it stays out of the product's marketing/UI surfaces
> while remaining available for license review. It is the **only** place in the
> project where specific external tool names appear.

## Orchestrated tools and their licenses

| Tool | License | Note |
|---|---|---|
| nmap | NPSL | Redistribution / commercial-bundling restrictions — do **not** ship it inside a commercial image without review. |
| WPScan | Non-commercial (WPScan license) | Free for non-commercial use; a commercial WPScan license / API token is required otherwise. |
| MobSF | GPL-3.0 | Copyleft — bundling in a distributed image carries GPL obligations. |
| nuclei, trivy, semgrep, prowler, kube-bench | Apache-2.0 / MIT | Permissive. |

The default container image installs only permissively-licensed tools; nmap,
WPScan and MobSF are expected to be provided by the operator. Corvex-RedOps's own
SCA engine emits CycloneDX SBOMs for scanned targets; a signed project-level SBOM
and a clean licence attestation are tracked on the roadmap.

**Have licensing reviewed before any commercial distribution or paid tier.**
For the Premium edition, remove any tool from the shipped image whose license you
do not intend to comply with, and trim this file to match what is actually
distributed.
