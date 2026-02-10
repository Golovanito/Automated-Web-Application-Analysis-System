import sqlite3
import json
from typing import Optional, List, Dict, Any

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_items (
    id TEXT PRIMARY KEY,
    data JSON
);
CREATE INDEX IF NOT EXISTS idx_cve_id ON cve_items(id);
"""

class CVEStore:
    def __init__(self, path: str = "cve_store.db"):
        self.path = path
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.executescript(DB_SCHEMA)
        self.conn.commit()

    def bulk_insert(self, items: List[Dict[str, Any]]):
        # insert list of records
        cur = self.conn.cursor()
        for item in items:
            if not isinstance(item, dict):
                continue
            cve_id = None
            # NVD 1.1
            cve = item.get("cve")
            if isinstance(cve, dict):
                meta = cve.get("CVE_data_meta")
                if isinstance(meta, dict) and "ID" in meta:
                    cve_id = meta["ID"]
                # NVD 2.0
                if not cve_id and "id" in cve:
                    cve_id = cve["id"]
            if not cve_id:
                cve_id = item.get("id") or item.get("CVE") or item.get("ID")
            if not cve_id:
                continue
            cur.execute(
                "INSERT OR REPLACE INTO cve_items (id, data) VALUES (?, ?);",
                (cve_id, json.dumps(item))
            )
        self.conn.commit()

    def get_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        r = cur.execute("SELECT data FROM cve_items WHERE id = ?;", (cve_id,)).fetchone()
        return json.loads(r[0]) if r else None

    def search_by_text(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        q = f"%{query.lower()}%"
        rows = self.conn.execute(
            "SELECT data FROM cve_items WHERE lower(data) LIKE ? LIMIT ?;",
            (q, limit)
        ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def count(self) -> int:
        cur = self.conn.cursor()
        return cur.execute("SELECT COUNT(1) FROM cve_items;").fetchone()[0]

    def close(self):
        self.conn.close()