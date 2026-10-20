"""SQLite database layer for GuardRail.

Design Decision:
SQLite is embedded, zero-maintenance, and completely local, making the lab
easy to clone and run immediately. We use parameterized SQL queries everywhere
to demonstrate defense-in-depth against SQL injection (SQLi) at the database layer.
We also support in-memory databases (':memory:') for isolated, ultra-fast test runs.
"""

import sqlite3
from typing import Any, Dict, List, Optional
from guardrail.config import settings
from guardrail.storage.models import IncidentDocument, IncidentRecord, SecurityLogRecord


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create and return a configured SQLite connection with row factories."""
    path = db_path if db_path is not None else settings.database_path
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # Enable foreign key constraints in SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Initialize the database tables if they do not exist."""
    cursor = conn.cursor()

    # Table 1: Incidents
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            description TEXT NOT NULL,
            sensitivity_tier TEXT NOT NULL DEFAULT 'tier_1',
            created_at TEXT NOT NULL,
            assigned_analyst TEXT NOT NULL
        );
        """
    )

    # Table 2: Incident Documents (reports, notes, runbooks)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_documents (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            title TEXT NOT NULL,
            doc_type TEXT NOT NULL,
            content TEXT NOT NULL,
            classification TEXT NOT NULL DEFAULT 'internal',
            author TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE CASCADE
        );
        """
    )

    # Table 3: Security Logs (authentication, network, access logs)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_logs (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE CASCADE
        );
        """
    )

    conn.commit()


def get_all_incidents(conn: sqlite3.Connection) -> List[IncidentRecord]:
    """Retrieve all synthetic incidents."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id ASC;")
    rows = cursor.fetchall()
    return [IncidentRecord(**dict(row)) for row in rows]


def get_incident_by_id(conn: sqlite3.Connection, incident_id: str) -> Optional[IncidentRecord]:
    """Retrieve a single incident by its ID using parameterized query."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents WHERE id = ?;", (incident_id,))
    row = cursor.fetchone()
    if not row:
        return None
    return IncidentRecord(**dict(row))


def search_documents_db(
    conn: sqlite3.Connection,
    query: str,
    incident_id: Optional[str] = None,
    limit: int = 5,
) -> List[IncidentDocument]:
    """Search incident documents matching keyword in title or content using parameterized queries.

    Security Principle:
    Parameter binding (? placeholders) completely separates SQL code from user inputs.
    Even if 'query' contains SQL injection attempts (e.g. ' UNION SELECT ...),
    SQLite treats it strictly as a literal string.
    """
    cursor = conn.cursor()
    search_pattern = f"%{query}%"

    if incident_id:
        cursor.execute(
            """
            SELECT * FROM incident_documents
            WHERE incident_id = ? AND (title LIKE ? OR content LIKE ?)
            LIMIT ?;
            """,
            (incident_id, search_pattern, search_pattern, limit),
        )
    else:
        cursor.execute(
            """
            SELECT * FROM incident_documents
            WHERE title LIKE ? OR content LIKE ?
            LIMIT ?;
            """,
            (search_pattern, search_pattern, limit),
        )

    rows = cursor.fetchall()
    return [IncidentDocument(**dict(row)) for row in rows]


def query_security_logs_db(
    conn: sqlite3.Connection,
    incident_id: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 20,
) -> List[SecurityLogRecord]:
    """Query synthetic security logs with dynamic, fully parameterized filters.

    Security Principles:
    1. Parameterized Queries: All filter values are bound via '?' placeholders.
    2. Column Allowlisting: Only hardcoded, static column names are interpolated.
    3. Strict Limit: A bounded integer limit is always applied to prevent memory exhaustion.
    """
    cursor = conn.cursor()
    conditions = []
    params: List[Any] = []

    if incident_id:
        conditions.append("incident_id = ?")
        params.append(incident_id)
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if source_ip:
        conditions.append("source_ip = ?")
        params.append(source_ip)
    if status:
        conditions.append("status = ?")
        params.append(status)

    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
    sql = f"SELECT * FROM security_logs{where_clause} ORDER BY timestamp ASC LIMIT ?;"
    params.append(limit)

    cursor.execute(sql, tuple(params))
    rows = cursor.fetchall()
    return [SecurityLogRecord(**dict(row)) for row in rows]
