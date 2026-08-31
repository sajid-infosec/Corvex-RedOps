import time
from pentestiq.core.jobs import RateLimiter, LocalJobQueue


def test_local_queue_preserves_order_and_runs_parallel():
    def mk(i):
        def job():
            time.sleep(0.1)
            return i
        return job
    q = LocalJobQueue(max_concurrency=4)
    t0 = time.monotonic()
    out = q.run_all(mk(i) for i in range(4))
    elapsed = time.monotonic() - t0
    assert out == [0, 1, 2, 3]          # order preserved
    assert elapsed < 0.3                # 4x0.1s ran concurrently, not serially


def test_rate_limiter_throttles_per_host():
    rl = RateLimiter(rate_per_sec=20, burst=1)
    t0 = time.monotonic()
    for _ in range(3):
        rl.acquire("host-a")
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.08              # ~2 refills at 20/s


def test_rate_limiter_unlimited_is_instant():
    rl = RateLimiter(rate_per_sec=0)
    t0 = time.monotonic()
    for _ in range(1000):
        rl.acquire("h")
    assert (time.monotonic() - t0) < 0.05
