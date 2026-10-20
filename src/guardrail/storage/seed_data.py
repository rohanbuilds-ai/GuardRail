"""Reproducible synthetic security data generator for GuardRail.

Design Decision:
All data is 100% fictional and adheres to RFC 5737 documentation IP prefixes
(e.g., 198.51.100.0/24, 203.0.113.0/24). No real credentials, proprietary hostnames,
or real personal identifiable information (PII) are ever used.
Deterministic IDs (INC-001, DOC-001, LOG-001) allow automated test assertions.
"""

import sqlite3
from typing import Dict, List


SYNTHETIC_INCIDENTS: List[Dict[str, str]] = [
    {
        "id": "INC-001",
        "title": "Credential Stuffing Campaign Against GlobalProtect VPN",
        "severity": "high",
        "status": "investigating",
        "description": "Distributed automated authentication attempts detected against the perimeter VPN endpoint targeting engineer accounts.",
        "sensitivity_tier": "tier_1",
        "created_at": "2026-10-18T08:14:00Z",
        "assigned_analyst": "analyst_sarah",
    },
    {
        "id": "INC-002",
        "title": "Suspicious AWS S3 Data Sync Anomaly",
        "severity": "medium",
        "status": "investigating",
        "description": "Unusual outbound data transfer spikes observed from analytical staging bucket to an external IP.",
        "sensitivity_tier": "tier_1",
        "created_at": "2026-10-19T14:30:00Z",
        "assigned_analyst": "analyst_david",
    },
]

SYNTHETIC_DOCUMENTS: List[Dict[str, str]] = [
    {
        "id": "DOC-001",
        "incident_id": "INC-001",
        "title": "Initial SOC Triage Report - GlobalProtect VPN Anomaly",
        "doc_type": "initial_triage",
        "content": (
            "SOC Alert 8941 triggered at 08:14 UTC. High volume of failed Kerberos/RADIUS authentications "
            "against perimeter GlobalProtect VPN gateway originating from source IP 198.51.100.42. Over 450 attempts "
            "within 10 minutes targeting usernames matching pattern 'dev-*'. Account 'dev-svc-backup' experienced "
            "12 consecutive lockouts on the VPN portal. Recommendation: Block source subnet 198.51.100.0/24 "
            "at firewall boundary and force credential reset."
        ),
        "classification": "internal",
        "author": "soc_tier1_auto",
        "created_at": "2026-10-18T08:25:00Z",
    },
    {
        "id": "DOC-002",
        "incident_id": "INC-001",
        "title": "Analyst Investigation Notes - Threat Intelligence Correlation",
        "doc_type": "analyst_notes",
        "content": (
            "Correlated IP 198.51.100.42 with known bulletproof hosting infrastructure (AS64496) targeting VPN services. "
            "User-Agent strings observed: 'Python-urllib/3.10' and 'Mozilla/5.0 (Hydra-v9)'. "
            "No successful authentications recorded on the VPN gateway from this IP as of 09:00 UTC. "
            "Perimeter WAF rate-limiting rule WAF-RL-042 successfully mitigated subsequent packets."
        ),
        "classification": "internal",
        "author": "analyst_sarah",
        "created_at": "2026-10-18T09:10:00Z",
    },
    {
        "id": "DOC-003",
        "incident_id": "INC-002",
        "title": "DLP Staging Alert Summary - INC-002",
        "doc_type": "forensics_report",
        "content": (
            "Automated CloudWatch alarm 'EgressBytesExceeded' alerted on bucket 'corp-analytics-staging-prod'. "
            "Destination IP 203.0.113.88 received 14.2 GB of encrypted parquet archives between 14:00 and 14:22 UTC. "
            "IAM role 'AnalyticsSyncWorker' assumed from EC2 instance i-0abcdef1234567890. "
            "Initial review shows scheduled backup job was reconfigured with modified destination endpoint."
        ),
        "classification": "internal",
        "author": "analyst_david",
        "created_at": "2026-10-19T14:45:00Z",
    },
]

SYNTHETIC_LOGS: List[Dict[str, str]] = [
    {
        "id": "LOG-001",
        "incident_id": "INC-001",
        "timestamp": "2026-10-18T08:14:02Z",
        "event_type": "AUTH_FAILED",
        "source_ip": "198.51.100.42",
        "destination_ip": "192.0.2.1",
        "user_id": "dev-alex",
        "action": "VPN_LOGIN",
        "status": "FAILED",
        "details": "Invalid password signature (RADIUS error 101)",
    },
    {
        "id": "LOG-002",
        "incident_id": "INC-001",
        "timestamp": "2026-10-18T08:14:05Z",
        "event_type": "AUTH_FAILED",
        "source_ip": "198.51.100.42",
        "destination_ip": "192.0.2.1",
        "user_id": "dev-svc-backup",
        "action": "VPN_LOGIN",
        "status": "FAILED",
        "details": "Account locked out after 5 consecutive failed attempts",
    },
    {
        "id": "LOG-003",
        "incident_id": "INC-002",
        "timestamp": "2026-10-19T14:05:12Z",
        "event_type": "S3_GET_OBJECT",
        "source_ip": "10.0.1.15",
        "destination_ip": "203.0.113.88",
        "user_id": "AnalyticsSyncWorker",
        "action": "S3_EXPORT",
        "status": "SUCCESS",
        "details": "Transferred 4.2GB object /staging/archive_2026_q3.parquet",
    },
]


def seed_database(conn: sqlite3.Connection) -> None:
    """Populate the database with synthetic incident data if not already present."""
    cursor = conn.cursor()

    for inc in SYNTHETIC_INCIDENTS:
        cursor.execute(
            """
            INSERT OR REPLACE INTO incidents
            (id, title, severity, status, description, sensitivity_tier, created_at, assigned_analyst)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                inc["id"],
                inc["title"],
                inc["severity"],
                inc["status"],
                inc["description"],
                inc["sensitivity_tier"],
                inc["created_at"],
                inc["assigned_analyst"],
            ),
        )

    for doc in SYNTHETIC_DOCUMENTS:
        cursor.execute(
            """
            INSERT OR REPLACE INTO incident_documents
            (id, incident_id, title, doc_type, content, classification, author, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                doc["id"],
                doc["incident_id"],
                doc["title"],
                doc["doc_type"],
                doc["content"],
                doc["classification"],
                doc["author"],
                doc["created_at"],
            ),
        )

    for log in SYNTHETIC_LOGS:
        cursor.execute(
            """
            INSERT OR REPLACE INTO security_logs
            (id, incident_id, timestamp, event_type, source_ip, destination_ip, user_id, action, status, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                log["id"],
                log["incident_id"],
                log["timestamp"],
                log["event_type"],
                log["source_ip"],
                log["destination_ip"],
                log["user_id"],
                log["action"],
                log["status"],
                log["details"],
            ),
        )

    conn.commit()
