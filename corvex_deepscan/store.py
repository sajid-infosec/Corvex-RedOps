"""SQLite-backed persistence for captured flows.

Bodies are stored as best-effort decoded text (capped) because the analysis
layer works on text. The content-type is preserved so binary payloads can be
skipped during analysis.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterator, Optional

from .models import CapturedRequest, CapturedResponse, Flow

DEFAULT_BODY_CAP = 5 * 1024 * 1024  # 5 MB per body

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL,
    method        TEXT,
    scheme        TEXT,
    host          TEXT,
    port          INTEGER,
    path          TEXT,
    url           TEXT,
    status        INTEGER,
    mime          TEXT,
    duration_ms   REAL,
    req_query     TEXT,
    req_headers   TEXT,
    req_body      TEXT,
    req_trunc     INTEGER,
    resp_headers  TEXT,
    resp_body     TEXT,
    resp_trunc    INTEGER,
    resp_reason   TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(status);
CREATE INDEX IF NOT EXISTS idx_flows_path ON flows(path);
"""


class FlowStore:
    def __init__(self, path: str = ":memory:", body_cap: int = DEFAULT_BODY_CAP):
        self.path = path
        self.body_cap = body_cap
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- write ---------------------------------------------------------------
    def _cap(self, body: str) -> tuple[str, bool]:
        if body and len(body) > self.body_cap:
            return body[: self.body_cap], True
        return body or "", False

    def save_flow(self, flow: Flow) -> int:
        req, resp = flow.request, flow.response
        req_body, req_trunc = self._cap(req.body)
        resp_body, resp_trunc = (self._cap(resp.body) if resp else ("", False))
        cur = self._conn.execute(
            """INSERT INTO flows (ts, method, scheme, host, port, path, url, status,
                   mime, duration_ms, req_query, req_headers, req_body, req_trunc,
                   resp_headers, resp_body, resp_trunc, resp_reason)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                req.timestamp, req.method, req.scheme, req.host, req.port, req.path,
                req.url, resp.status_code if resp else None,
                resp.mime if resp else "", flow.duration_ms,
                json.dumps(req.query), json.dumps(req.headers),
                req_body, int(req_trunc or req.body_truncated),
                json.dumps(resp.headers) if resp else "[]",
                resp_body, int(resp_trunc or (resp.body_truncated if resp else False)),
                resp.reason if resp else "",
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    # -- read ----------------------------------------------------------------
    def _row_to_flow(self, row: sqlite3.Row) -> Flow:
        req = CapturedRequest(
            method=row["method"], url=row["url"], scheme=row["scheme"],
            host=row["host"], port=row["port"], path=row["path"],
            query=[tuple(x) for x in json.loads(row["req_query"] or "[]")],
            headers=[tuple(x) for x in json.loads(row["req_headers"] or "[]")],
            body=row["req_body"] or "", body_truncated=bool(row["req_trunc"]),
            timestamp=row["ts"] or 0.0,
        )
        resp = None
        if row["status"] is not None:
            resp = CapturedResponse(
                status_code=row["status"], reason=row["resp_reason"] or "",
                headers=[tuple(x) for x in json.loads(row["resp_headers"] or "[]")],
                body=row["resp_body"] or "", body_truncated=bool(row["resp_trunc"]),
                mime=row["mime"] or "",
            )
        return Flow(request=req, response=resp, id=row["id"],
                    duration_ms=row["duration_ms"] or 0.0)

    def iter_flows(self, host: Optional[str] = None) -> Iterator[Flow]:
        q = "SELECT * FROM flows"
        args: tuple = ()
        if host:
            q += " WHERE host = ?"
            args = (host,)
        q += " ORDER BY id"
        for row in self._conn.execute(q, args):
            yield self._row_to_flow(row)

    def get_flow(self, flow_id: int) -> Optional[Flow]:
        row = self._conn.execute(
            "SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        return self._row_to_flow(row) if row else None

    def summaries(self, limit: int = 500) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, method, host, path, status FROM flows ORDER BY id LIMIT ?",
            (limit,))
        return [{"id": r["id"], "method": r["method"], "host": r["host"],
                 "path": r["path"], "status": r["status"]} for r in rows]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]

    def hosts(self) -> list[str]:
        return [r[0] for r in self._conn.execute(
            "SELECT DISTINCT host FROM flows ORDER BY host")]

    def close(self) -> None:
        self._conn.close()
