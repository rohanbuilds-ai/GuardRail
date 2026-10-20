"""Tool 2: query_security_logs

Purpose:
Retrieve matching synthetic security log records (authentication events, network traffic, access logs).

Security Requirements:
1. Strict parameter bounds: limit is bounded between 1 and 50.
2. Parameterized SQL queries: No dynamic SQL construction from user input.
3. Untrusted Data Tagging: Logs returned from data storage are untrusted data.
"""

import sqlite3
from typing import List, Optional
from pydantic import BaseModel, Field
from guardrail.storage.database import query_security_logs_db
from guardrail.storage.models import SecurityLogRecord


class QueryLogsInput(BaseModel):
    """Validated input parameters for querying synthetic security logs."""

    incident_id: Optional[str] = Field(
        None,
        pattern=r"^INC-\d{3}$",
        description="Filter logs by incident ID (e.g. INC-001)",
    )
    event_type: Optional[str] = Field(
        None,
        max_length=50,
        description="Filter by event type (e.g. AUTH_FAILED, S3_EXPORT)",
    )
    source_ip: Optional[str] = Field(
        None,
        max_length=45,
        description="Filter by source IP address (e.g. 198.51.100.42)",
    )
    status: Optional[str] = Field(
        None,
        max_length=20,
        description="Filter by status (e.g. SUCCESS, FAILED)",
    )
    limit: int = Field(
        default=20,
        ge=1,
        le=50,
        description="Maximum number of log records to return (1-50)",
    )


class QueryLogsOutput(BaseModel):
    """Output envelope returned by query_security_logs."""

    total_found: int
    incident_id: Optional[str] = None
    event_type: Optional[str] = None
    logs: List[SecurityLogRecord]
    trust_level: str = "untrusted_retrieved_data"


def query_security_logs(
    input_params: QueryLogsInput,
    conn: sqlite3.Connection,
) -> QueryLogsOutput:
    """Execute bounded query over synthetic security logs."""
    logs = query_security_logs_db(
        conn=conn,
        incident_id=input_params.incident_id,
        event_type=input_params.event_type,
        source_ip=input_params.source_ip,
        status=input_params.status,
        limit=input_params.limit,
    )

    return QueryLogsOutput(
        total_found=len(logs),
        incident_id=input_params.incident_id,
        event_type=input_params.event_type,
        logs=logs,
    )
