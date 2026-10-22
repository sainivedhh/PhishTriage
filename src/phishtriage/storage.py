"""SQLite incident and evaluation storage repository."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
from phishtriage.models import IncidentReport


class Storage:
    def __init__(self, db_path: str | Path = "phishtriage.db"):
        self.db_path = str(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._conn = sqlite3.connect(":memory:")
            self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    email_subject TEXT,
                    sender TEXT,
                    recipient TEXT,
                    verdict TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    mitre_techniques TEXT,
                    iocs_json TEXT,
                    report_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_incidents_verdict ON incidents(verdict)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_incidents_score ON incidents(score)
                """
            )
            conn.commit()

    def save_incident(self, report: IncidentReport) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id, created_at, email_subject, sender, recipient,
                    verdict, score, mitre_techniques, iocs_json, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.incident_id,
                    report.created_at.isoformat(),
                    report.email_subject,
                    report.sender,
                    report.recipient,
                    report.verdict.value,
                    report.score,
                    ",".join(report.mitre_techniques),
                    json.dumps(report.iocs),
                    report.model_dump_json(),
                ),
            )
            conn.commit()

    def get_incident(self, incident_id: str) -> Optional[IncidentReport]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT report_json FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return IncidentReport.model_validate_json(row["report_json"])

    def list_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT incident_id, created_at, email_subject, sender, verdict, score
                FROM incidents
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
