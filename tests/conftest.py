"""Shared test configuration.

Pins the first-run admin credentials and forces offline threat-intel so the
whole suite is deterministic and network-free. Production ships NO default
password — one is generated and logged on first boot (see AuthService).
"""
import os

import pytest

# Pin the seeded admin so existing tests can log in with known credentials.
os.environ.setdefault("CORVEX_ADMIN_USER", "pentestiq")
os.environ.setdefault("CORVEX_ADMIN_PASSWORD", "p3nt3st!q-admin")
# The pinned test admin skips the first-sign-in forced change (the documented opt-out for
# automated provisioning). tests/test_first_run_admin.py exercises the forced change itself.
os.environ.setdefault("CORVEX_ADMIN_FORCE_CHANGE", "0")
# Many tests create their own tenants through POST /auth/register; production keeps it closed.
# tests/test_registration.py exercises the closed default.
os.environ.setdefault("CORVEX_ALLOW_REGISTRATION", "1")
# Never touch the network during tests (EPSS/KEV lookups, etc.).
os.environ.setdefault("PENTESTIQ_INTEL_OFFLINE", "1")
# Never contact the account registry from tests; tests that need it inject a fake.
os.environ.setdefault("CORVEX_REGISTRY", "off")
# Never launch a headless browser in the test/CI environment (would hang or need
# a full browser stack); the native BFS crawler still runs.
os.environ.setdefault("CORVEX_SPA_CRAWL", "0")
# Exercise the full feature surface by default so edition gating is transparent to
# the rest of the suite; tests/test_edition.py overrides this per-test to assert the
# Community gating behaviour explicitly.
os.environ.setdefault("CORVEX_EDITION", "enterprise")


# ---- the sign-in throttle's clock ---------------------------------------------------------
# The throttle counts in fixed windows (15 minutes per username+IP and per IP; an hour per
# username) that restart at :00, :15, :30 and :45. A test that counted attempts across one of
# those boundaries saw its counts reset (CI did, at 08:15:00 UTC). So every test runs with the
# throttle's clock pinned 7.5 minutes into a 15-minute window and mid-hour (hh:37:30); session
# issue and expiry still use the real time. A test that needs time to move sets
# `throttle_clock.t`.

THROTTLE_HOUR = 1_800_000_000 - 1_800_000_000 % 3600     # hh:00:00
THROTTLE_PINNED = THROTTLE_HOUR + 30 * 60 + 450           # hh:37:30


class ThrottleClock:
    """Stands in for pentestiq.auth.service._throttle_now; `t` is the time in seconds."""

    def __init__(self, t: int):
        self.t = t

    def __call__(self) -> int:
        return int(self.t)


@pytest.fixture(autouse=True)
def throttle_clock(monkeypatch):
    import pentestiq.auth.service as svc
    clock = ThrottleClock(THROTTLE_PINNED)
    monkeypatch.setattr(svc, "_throttle_now", clock)
    return clock
