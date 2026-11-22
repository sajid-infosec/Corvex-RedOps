"""The auth store runs SQLite in WAL mode with synchronous=NORMAL and a busy timeout, so a
commit doesn't wait for the disk; existing databases switch on first open and stay switched;
the documented backup (SQLite's backup API) captures what a plain copy of the .db misses."""
import logging
import shutil
import sqlite3
from pathlib import Path

from pentestiq.auth.models import Role
from pentestiq.storage import SqliteAuthStore
from pentestiq.storage.compat import BUSY_TIMEOUT_MS, use_wal

ROOT = Path(__file__).resolve().parents[1]


def _pragmas(conn):
    return tuple(conn.execute(f"PRAGMA {p}").fetchone()[0] for p in ("journal_mode", "synchronous", "busy_timeout"))


def test_auth_connection_is_wal_normal_with_a_busy_timeout(tmp_path):
    s = SqliteAuthStore(str(tmp_path / "pentestiq.db"))
    assert _pragmas(s._conn) == ("wal", 1, BUSY_TIMEOUT_MS)          # synchronous 1 = NORMAL


def test_a_reopened_database_stays_in_wal(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    SqliteAuthStore(db)._conn.close()
    plain = sqlite3.connect(db)                                       # no pragmas of its own
    assert plain.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    plain.close()
    assert _pragmas(SqliteAuthStore(db)._conn)[0] == "wal"


def test_an_existing_rollback_journal_database_switches_on_first_open(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    old = sqlite3.connect(db)
    assert old.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
    old.execute("CREATE TABLE engagements (id TEXT)")                 # another store's data
    old.execute("INSERT INTO engagements VALUES ('e1')"); old.commit(); old.close()
    s = SqliteAuthStore(db)
    assert _pragmas(s._conn)[0] == "wal"
    assert s._conn.execute("SELECT id FROM engagements").fetchone()[0] == "e1"


def test_in_memory_databases_still_work(caplog):
    with caplog.at_level(logging.WARNING, logger="pentestiq.storage"):
        s = SqliteAuthStore(":memory:")
    assert _pragmas(s._conn)[0] == "memory" and not caplog.records


def test_a_refused_switch_is_logged(caplog):
    class NoWal:                                     # e.g. a filesystem without shared memory
        def __init__(self):
            self._c = sqlite3.connect(":memory:")

        def execute(self, sql):
            if sql == "PRAGMA journal_mode=WAL":
                return self._c.execute("SELECT 'delete'")
            return self._c.execute(sql)
    with caplog.at_level(logging.WARNING, logger="pentestiq.storage"):
        assert use_wal(NoWal()) == "delete"
    assert "local disk" in caplog.text


def test_backup_api_captures_what_a_plain_copy_of_the_db_misses(tmp_path):
    db = tmp_path / "pentestiq.db"
    s = SqliteAuthStore(str(db))
    s.create_user("alice", "pbkdf2_sha256$1$00$00")                  # committed, still in the WAL
    assert (tmp_path / "pentestiq.db-wal").stat().st_size > 0
    shutil.copy(db, tmp_path / "copy.db")                             # the unsafe backup
    copy = sqlite3.connect(tmp_path / "copy.db")
    assert copy.execute("SELECT name FROM sqlite_master WHERE name = 'users'").fetchone() is None
    copy.close()
    dest = sqlite3.connect(tmp_path / "backup.db")                    # the documented backup
    sqlite3.connect(db).backup(dest)
    assert dest.execute("SELECT username FROM users").fetchone()[0] == "alice"
    dest.close()


def test_docs_say_local_disk_and_how_to_back_up():
    for name in ("README.md", "INSTALL.md"):
        t = (ROOT / name).read_text(encoding="utf-8")
        assert "**Keep the data directory on a local disk, not NFS or SMB/CIFS.**" in t, name
        assert ".backup 'corvex-redops-backup.db'" in t and ".backup(d)" in t, name
        assert "Never copy `corvex-redops.db` alone" in t and "corvex-redops.db-wal" in t, name
    assert "local disk, not NFS or SMB/CIFS" in (ROOT / "docs/DEPLOYMENT.md").read_text(encoding="utf-8")


def test_request_path_reads_use_a_separate_wal_reader_that_sees_every_commit(tmp_path):
    s = SqliteAuthStore(str(tmp_path / "pentestiq.db"))
    assert s._rconn is not s._conn and _pragmas(s._rconn) == ("wal", 1, BUSY_TIMEOUT_MS)
    t = s.create_tenant("t"); u = s.create_user("bob", "x"); s.add_membership(u.id, t.id, Role.ADMIN)
    assert s.get_session_state(u.id, t.id) == {"role": "admin", "sessions_valid_after": 0}
    for at in (1, 2, 3):                                      # each write is visible at once
        s.end_sessions("bob", at)
        assert s.get_session_state(u.id, t.id)["sessions_valid_after"] == at
    s.set_must_change_password("bob", True)
    assert s.must_change_password(u.id) is True
    # the reader doesn't wait for the writer: it answers while the write lock is held
    with s._lock:
        assert s.must_change_password(u.id) is True


def test_in_memory_store_reads_through_its_own_connection():
    s = SqliteAuthStore(":memory:")
    assert s._rconn is s._conn
    t = s.create_tenant("t"); u = s.create_user("bob", "x"); s.add_membership(u.id, t.id, Role.VIEWER)
    assert s.get_session_state(u.id, t.id)["role"] == "viewer"
