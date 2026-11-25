"""Every decision is saved in SQLite so you can show it on the dashboard and in the report."""
import hashlib
import os
import sqlite3
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, run_tag TEXT, kind TEXT, source TEXT, tool TEXT,
  action TEXT, layer TEXT, score REAL, reason TEXT,
  snippet TEXT, text_hash TEXT, latency_ms REAL
)"""


class EventLog:
    def __init__(self, path=None, run_tag="live", store_snippet=True):
        self.path = str(path or os.environ.get("FW_DB", ROOT / "firewall.db"))
        self.run_tag = run_tag
        self.store_snippet = store_snippet
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute(SCHEMA)
        self._db.commit()

    def add(self, kind, source, action, layer, score, reason, latency_ms, text="", tool=""):
        h = hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:12] if text else ""
        snip = text[:80].replace("\n", " ") if (text and self.store_snippet) else ""
        with self._lock:
            self._db.execute(
                "INSERT INTO events(ts,run_tag,kind,source,tool,action,layer,score,reason,snippet,text_hash,latency_ms)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), self.run_tag, kind, source, tool, action, layer, float(score), reason, snip, h, float(latency_ms)),
            )
            self._db.commit()

    def recent(self, n=100):
        with self._lock:
            cur = self._db.execute(
                "SELECT ts,run_tag,kind,source,tool,action,layer,score,reason,snippet,latency_ms FROM events ORDER BY id DESC LIMIT ?",
                (n,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
