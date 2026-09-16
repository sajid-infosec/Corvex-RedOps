# Contributing to Corvex

Thanks for your interest! Contribution guidelines will expand as the project
matures. For now:

- **Modules** live under `modules/<asset-type>/` and implement the standard
  module interface (see `docs/ARCHITECTURE.md`).
- **Tool integrations** live under `integrations/` and wrap an external tool
  into the normalized findings model.
- All new exploit/validation logic MUST respect safe-mode and authorization
  gating. PRs that bypass these will not be accepted.
- Add tests under `tests/` for parsers and correlation logic.

Open an issue to discuss significant changes before submitting a PR.
