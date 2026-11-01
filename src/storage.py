"""Bounded durable incident journal and executable-hash allow rules."""

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


class IncidentStore:
    def __init__(self, directory, retention_days=30, max_incidents=10000):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "incidents.sqlite3"
        self.retention_days, self.max_incidents = retention_days, max_incidents
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, timestamp REAL NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS incident_time ON incidents(timestamp);
                CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, executable TEXT NOT NULL, sha256 TEXT NOT NULL, reason TEXT NOT NULL, created REAL NOT NULL, UNIQUE(executable,sha256));
                CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, digest TEXT NOT NULL, timestamp REAL NOT NULL, result TEXT);
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            """)
        self.prune()

    def claim_workspace(self, kind):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value FROM metadata WHERE key='workspace_kind'").fetchone()
            if row and row[0] != kind:
                raise ValueError("Demo and live workspaces must use different storage directories")
            if not row:
                existing = db.execute("SELECT payload FROM incidents LIMIT 1").fetchone()
                if existing:
                    inferred = (
                        "demo"
                        if json.loads(existing[0]).get("evidence", {}).get("source") == "demo"
                        else "live"
                    )
                    if inferred != kind:
                        raise ValueError(
                            "Existing incident records belong to a different workspace kind"
                        )
                db.execute("INSERT OR REPLACE INTO metadata VALUES('workspace_kind',?)", (kind,))

    def management_load(self, policy, reset=False):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value FROM metadata WHERE key='management'").fetchone()
            state = json.loads(row[0]) if row else None
            if state is None or reset:
                state = {
                    "revision": state["revision"] + 1 if state else 1,
                    "policy": policy,
                    "desired": "running",
                    "pause_until": None,
                    "updated_at": time.time(),
                    "reason": "Startup policy reset" if reset else "Initial startup policy",
                }
                db.execute(
                    "INSERT OR REPLACE INTO metadata VALUES('management',?)", (json.dumps(state),)
                )
            pending = db.execute(
                "SELECT value FROM metadata WHERE key='management_transition'"
            ).fetchone()
        return state, bool(pending)

    def management_transition(self, revision, details):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value FROM metadata WHERE key='management'").fetchone()
            if not row or json.loads(row[0])["revision"] != revision:
                raise ValueError("Policy revision changed; refresh before applying")
            db.execute(
                "INSERT OR REPLACE INTO metadata VALUES('management_transition',?)",
                (json.dumps(details),),
            )

    def management_commit(self, revision, state):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value FROM metadata WHERE key='management'").fetchone()
            if not row or json.loads(row[0])["revision"] != revision:
                raise ValueError("Policy revision changed; refresh before applying")
            committed = {**state, "revision": revision + 1, "updated_at": time.time()}
            db.execute(
                "INSERT OR REPLACE INTO metadata VALUES('management',?)", (json.dumps(committed),)
            )
            db.execute("DELETE FROM metadata WHERE key='management_transition'")
        return committed

    def management_rollback(self):
        with self.connect() as db:
            db.execute("DELETE FROM metadata WHERE key='management_transition'")

    def audit_events(self, limit=30):
        with self.connect() as db:
            rows = db.execute(
                "SELECT id,timestamp,payload FROM audit ORDER BY id DESC LIMIT ?",
                (min(limit, 100),),
            ).fetchall()
        return [{"id": row[0], "timestamp": row[1], **json.loads(row[2])} for row in rows]

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA busy_timeout=5000")
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, incident):
        item = incident.to_dict() if hasattr(incident, "to_dict") else incident
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO incidents VALUES(?,?,?,?)",
                (item["id"], item["timestamp"], item["status"], json.dumps(item, allow_nan=False)),
            )
            db.execute(
                "DELETE FROM incidents WHERE id NOT IN (SELECT id FROM incidents ORDER BY timestamp DESC LIMIT ?)",
                (self.max_incidents,),
            )
        return item

    def get(self, incident_id):
        with self.connect() as db:
            row = db.execute("SELECT payload FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def export(self):
        with self.connect() as db:
            rows = db.execute(
                "SELECT payload FROM incidents ORDER BY timestamp DESC LIMIT ?",
                (self.max_incidents,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def list(self, limit=200):
        with self.connect() as db:
            rows = db.execute(
                "SELECT payload FROM incidents ORDER BY timestamp DESC LIMIT ?",
                (min(max(limit, 1), 1000),),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def audit(self, action):
        with self.connect() as db:
            db.execute(
                "INSERT INTO audit(timestamp,payload) VALUES(?,?)",
                (time.time(), json.dumps(action, allow_nan=False)),
            )
            db.execute(
                "DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 20000)"
            )

    def reserve_command(self, command):
        fingerprint = hashlib.sha256(json.dumps(command, sort_keys=True).encode()).hexdigest()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT digest,result FROM requests WHERE id=?", (command["request_id"],)
            ).fetchone()
            if row:
                if row[0] != fingerprint:
                    return "replay", {
                        "status": "refused",
                        "reason": "Request ID already belongs to a different command",
                    }
                return "replay", json.loads(row[1]) if row[1] else {
                    "status": "refused",
                    "reason": "Prior command outcome is unverified; review the incident before issuing a new request",
                }
            if db.execute("SELECT count(*) FROM requests").fetchone()[0] >= 20000:
                return "replay", {"status": "refused", "reason": "Command journal capacity reached"}
            db.execute(
                "INSERT INTO requests VALUES(?,?,?,NULL)",
                (command["request_id"], fingerprint, time.time()),
            )
            return "new", None

    def finish_command(self, request_id, result):
        with self.connect() as db:
            db.execute("UPDATE requests SET result=? WHERE id=?", (json.dumps(result), request_id))

    def add_rule(self, executable, sha256, reason):
        item = {
            "id": str(uuid4()),
            "executable": executable,
            "sha256": sha256,
            "reason": reason[:512],
            "created": time.time(),
        }
        with self.connect() as db:
            if db.execute("SELECT count(*) FROM rules").fetchone()[0] >= 1000:
                raise ValueError("Executable rule limit reached")
            db.execute("INSERT OR REPLACE INTO rules VALUES(?,?,?,?,?)", tuple(item.values()))
        return item

    def rules(self):
        with self.connect() as db:
            rows = db.execute(
                "SELECT id,executable,sha256,reason,created FROM rules ORDER BY created DESC LIMIT 1000"
            ).fetchall()
        return [
            dict(zip(("id", "executable", "sha256", "reason", "created"), row, strict=True))
            for row in rows
        ]

    def remove_rule(self, rule_id):
        with self.connect() as db:
            return db.execute("DELETE FROM rules WHERE id=?", (rule_id,)).rowcount > 0

    def prune(self):
        with self.connect() as db:
            db.execute(
                "DELETE FROM requests WHERE timestamp < ?",
                (time.time() - self.retention_days * 86400,),
            )
            db.execute(
                "DELETE FROM incidents WHERE timestamp < ?",
                (time.time() - self.retention_days * 86400,),
            )
            db.execute(
                "DELETE FROM incidents WHERE id NOT IN (SELECT id FROM incidents ORDER BY timestamp DESC LIMIT ?)",
                (self.max_incidents,),
            )

    def counts(self):
        with self.connect() as db:
            total = db.execute("SELECT count(*) FROM incidents").fetchone()[0]
            open_count = db.execute(
                "SELECT count(*) FROM incidents WHERE status='open'"
            ).fetchone()[0]
        return {"retained_incidents": total, "open_incidents": open_count}
