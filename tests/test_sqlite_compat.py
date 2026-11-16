"""SQLite compatibility: sign-in counters work without RETURNING (SQLite < 3.35, e.g.
Enterprise Linux 9's 3.34.1), and no SQL in the codebase needs a 3.35+ feature."""
import re
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pentestiq.storage import SqliteAuthStore

ROOT = Path(__file__).resolve().parents[1]


class NoReturning:
    """A connection proxy that behaves like SQLite 3.34: RETURNING is a syntax error."""

    def __init__(self, conn):
        self._c = conn

    def execute(self, sql, *a):
        if re.search(r"\bRETURNING\b", sql, re.I):
            raise sqlite3.OperationalError('near "RETURNING": syntax error')
        return self._c.execute(sql, *a)

    def __getattr__(self, name):
        return getattr(self._c, name)


def _store(tmp_path):
    s = SqliteAuthStore(str(tmp_path / "a.db"))
    s._conn = NoReturning(s._conn)
    return s


def test_reserve_works_without_returning(tmp_path):
    s = _store(tmp_path)
    keys = [("user-ip:a|1.2.3.4", 900), ("ip:1.2.3.4", 900), ("user-hour:a", 3600)]
    assert s.reserve_login_attempt(keys) == [1, 1, 1]
    assert s.reserve_login_attempt(keys) == [2, 2, 2]
    s.refund_login_attempt(keys)
    assert s.reserve_login_attempt(keys) == [2, 2, 2]
    # a key shared with another attempt keeps its own count
    assert s.reserve_login_attempt([("user-ip:b|1.2.3.4", 900), ("ip:1.2.3.4", 900), ("user-hour:b", 3600)]) == [1, 3, 1]


def test_reserve_is_atomic_across_threads_without_returning(tmp_path):
    s = _store(tmp_path)
    keys = [("user-ip:a|1.2.3.4", 900), ("ip:1.2.3.4", 900), ("user-hour:a", 3600)]
    start = threading.Barrier(40)

    def one(_):
        start.wait()
        return s.reserve_login_attempt(keys)[0]
    with ThreadPoolExecutor(40) as ex:
        seen = sorted(ex.map(one, range(40)))
    assert seen == list(range(1, 41))            # every concurrent attempt saw a distinct count


# SQL keywords in this codebase are upper case: match them case-sensitively so English prose
# ("...or returning records") isn't flagged; function names are matched in any case.
SYNTAX_335 = re.compile(r"\bRETURNING\b|\bDROP\s+COLUMN\b|(?i:\bunixepoch\s*\()|->>|\)\s*STRICT\b")
MATH_335 = re.compile(r"\b(sqrt|pow|power|ln|log2|log10|ceil|ceiling|trunc|degrees|radians|acos|asin|atan)\s*\(", re.I)
SQL_WORD = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|WHERE|SET)\b")


def sqlite_335_hits(text: str, name: str = "") -> list[str]:
    """Lines with a string literal using 3.35+ SQL syntax (or 3.35 math functions in SQL)."""
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0]
        if not re.search(r"[\"']", code):
            continue                              # SQL lives in string literals; skip prose/docstring text
        if SYNTAX_335.search(code) or (SQL_WORD.search(code) and MATH_335.search(code)):
            hits.append(f"{name}:{n}: {line.strip()[:120]}")
    return hits


def test_the_check_catches_the_old_returning_code():
    old = (
        '        sql = ("INSERT INTO login_failures (key, window_start, count) VALUES "\n'
        '               + ",".join(["(?, ?, 1)"] * len(keys))\n'
        '               + " RETURNING key, window_start, count")\n'
        '        c.execute("ALTER TABLE users DROP COLUMN x")\n'
        '        c.execute("SELECT sqrt(count) FROM t")\n'
    )
    assert len(sqlite_335_hits(old)) == 3


def test_no_sqlite_3_35_plus_features_in_the_codebase():
    hits = []
    for p in [f for base in [ROOT / "pentestiq", *sorted(ROOT.glob("corvex_*"))] for f in base.rglob("*.py")]:
        hits += sqlite_335_hits(p.read_text(encoding="utf-8"), str(p.relative_to(ROOT)))
    assert hits == []
