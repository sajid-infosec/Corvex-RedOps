"""Shared test configuration.

Pins the first-run admin credentials and forces offline threat-intel so the
whole suite is deterministic and network-free. Production ships NO default
password — one is generated and logged on first boot (see AuthService).
"""
import os

# Pin the seeded admin so existing tests can log in with known credentials.
os.environ.setdefault("CORVEX_ADMIN_USER", "pentestiq")
os.environ.setdefault("CORVEX_ADMIN_PASSWORD", "p3nt3st!q")
# Never touch the network during tests (EPSS/KEV lookups, etc.).
os.environ.setdefault("PENTESTIQ_INTEL_OFFLINE", "1")
# Never launch a headless browser in the test/CI environment (would hang or need
# a full browser stack); the native BFS crawler still runs.
os.environ.setdefault("CORVEX_SPA_CRAWL", "0")
