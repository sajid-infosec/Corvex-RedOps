"""Sign-in under concurrency: every attempt is counted atomically BEFORE the password check
(no burst bypass), and the slowdown is awaited (no blocked worker threads)."""
import asyncio
import time

import httpx

import pentestiq.auth.service as svc
from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


def _app(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_ADMIN_USER", "corvex")
    monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", "right-pass-123")
    monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", "0")
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    return create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path))), auth


def _client(app, ip):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 4000)), base_url="http://test")


def test_40_concurrent_wrong_passwords_from_one_address_reach_the_check_at_most_5_times(tmp_path, monkeypatch):
    app, _ = _app(tmp_path, monkeypatch)
    checks = []
    real = svc.verify_password

    def counting(pw, stored):
        checks.append(1)
        time.sleep(0.05)                     # a real hash takes time: widen the race window
        return real(pw, stored)
    monkeypatch.setattr(svc, "verify_password", counting)

    async def main():
        async with _client(app, "192.0.2.60") as c:
            rs = await asyncio.gather(*[c.post("/auth/login", json={"username": "corvex", "password": f"wrong-{i}-x"})
                                        for i in range(40)])
        return sorted(r.status_code for r in rs)
    codes = asyncio.run(main())
    assert len(checks) <= 5, f"{len(checks)} attempts reached the password check"
    assert codes.count(401) == len(checks) and codes.count(429) == 40 - len(checks)


def test_authenticated_requests_stay_fast_while_40_sign_ins_are_slowed(tmp_path, monkeypatch):
    app, auth = _app(tmp_path, monkeypatch)
    # a token for the real admin, then push the username past the hourly slowdown threshold
    async def token():
        async with _client(app, "203.0.113.1") as c:
            return (await c.post("/auth/login", json={"username": "corvex", "password": "right-pass-123"})).json()["token"]
    tok = asyncio.run(token())
    key, w = auth.attempt_keys("corvex", "x")[2]
    auth.store._conn.execute("INSERT INTO login_failures (key, window_start, count) VALUES (?, ?, 100) "
                             "ON CONFLICT(key, window_start) DO UPDATE SET count = 100", (key, w))
    auth.store._conn.commit()

    async def main():
        clients = [_client(app, f"198.51.100.{i + 1}") for i in range(40)]       # 40 addresses: no 429s
        t0 = time.monotonic()
        slow = [asyncio.create_task(c.post("/auth/login", json={"username": "corvex", "password": "wrong-pass-1"}))
                for c in clients]
        await asyncio.sleep(0.3)                                                 # all 40 now sleeping 1.5 s
        async with _client(app, "203.0.113.2") as me_client:
            t1 = time.monotonic()
            r = await me_client.get("/me", headers={"Authorization": "Bearer " + tok})
            me_took = time.monotonic() - t1
        codes = [x.status_code for x in await asyncio.gather(*slow)]
        total = time.monotonic() - t0
        for c in clients:
            await c.aclose()
        return r.status_code, me_took, codes, total
    status, me_took, codes, total = asyncio.run(main())
    assert status == 200
    assert me_took < 0.5, f"/me took {me_took:.2f}s while sign-ins were slowed"
    assert codes == [401] * 40 and total >= 1.5        # they really were slowed (and none locked out)
