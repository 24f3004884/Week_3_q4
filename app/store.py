import json
import sqlite3
import threading

from .config import DB_PATH

_lock = threading.Lock()
_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, isolation_level=None)
_conn.execute("PRAGMA journal_mode=WAL")
_conn.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, state TEXT NOT NULL)")
_conn.execute(
    "CREATE TABLE IF NOT EXISTS idem (run_id TEXT NOT NULL, k TEXT NOT NULL, hash TEXT NOT NULL, "
    "response TEXT NOT NULL, PRIMARY KEY (run_id, k))"
)


def get_state(run_id):
    with _lock:
        row = _conn.execute("SELECT state FROM runs WHERE run_id=?", (run_id,)).fetchone()
    return json.loads(row[0]) if row else None


def get_idem(run_id, key):
    with _lock:
        row = _conn.execute("SELECT hash, response FROM idem WHERE run_id=? AND k=?", (run_id, key)).fetchone()
    return (row[0], row[1]) if row else None


def commit(run_id, state, key, req_hash, response_text):
    with _lock:
        _conn.execute("BEGIN")
        try:
            _conn.execute("INSERT OR REPLACE INTO runs (run_id, state) VALUES (?, ?)", (run_id, json.dumps(state)))
            _conn.execute(
                "INSERT INTO idem (run_id, k, hash, response) VALUES (?, ?, ?, ?)",
                (run_id, key, req_hash, response_text),
            )
            _conn.execute("COMMIT")
        except Exception:
            _conn.execute("ROLLBACK")
            raise