"""Shared test configuration.

Pins the first-run admin credentials and forces offline threat-intel so the
whole suite is deterministic and network-free. Production ships NO default
password — one is generated and logged on first boot (see AuthService).
"""
import os

# Pin the seeded admin so existing tests can log in with known credentials.
os.environ.setdefault("CORVEX_ADMIN_USER", "pentestiq")
os.environ.setdefault("CORVEX_ADMIN_PASSWORD", "p3nt3st!q")
# The pinned test admin skips the first-sign-in forced change (the documented opt-out for
# automated provisioning). tests/test_first_run_admin.py exercises the forced change itself.
os.environ.setdefault("CORVEX_ADMIN_FORCE_CHANGE", "0")
# Many tests create their own tenants through POST /auth/register; production keeps it closed.
# tests/test_registration.py exercises the closed default.
os.environ.setdefault("CORVEX_ALLOW_REGISTRATION", "1")
# Never touch the network during tests (EPSS/KEV lookups, etc.).
os.environ.setdefault("PENTESTIQ_INTEL_OFFLINE", "1")
# Never launch a headless browser in the test/CI environment (would hang or need
# a full browser stack); the native BFS crawler still runs.
os.environ.setdefault("CORVEX_SPA_CRAWL", "0")
# Exercise the full feature surface by default so edition gating is transparent to
# the rest of the suite; tests/test_edition.py overrides this per-test to assert the
# Community gating behaviour explicitly.
os.environ.setdefault("CORVEX_EDITION", "enterprise")
