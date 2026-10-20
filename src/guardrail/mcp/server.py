"""GuardRail Standalone MCP Server.

Implements the Model Context Protocol (MCP) using the official SDK.
Exposes 3 read-only tools:
1. search_incident_documents
2. query_security_logs
3. get_incident_details

All operations are strictly read-only, parameterized, and operate exclusively
on synthetic security records.
"""

import json
from typing import Optional
from mcp.server.mcpserver import MCPServer
from pydantic import ValidationError

from guardrail.storage.database import get_db_connection
from guardrail.tools.incident_details import (
    IncidentDetailsInput,
    get_incident_details as execute_incident_details,
)
from guardrail.tools.query_logs import (
    QueryLogsInput,
    query_security_logs as execute_query_logs,
)
from guardrail.tools.search_docs import (
    SearchDocsInput,
    search_incident_documents as execute_search_docs,
)

mcp_server = MCPServer("guardrail-mcp")


@mcp_server.tool()
def search_incident_documents(
    query: str,
    incident_id: Optional[str] = None,
    limit: int = 5,
) -> str:
    """Search approved synthetic incident documentation and triage notes.

    Args:
        query: Search term or keyword (1-100 characters).
        incident_id: Optional incident filter formatted as INC-XXX (e.g. INC-001).
        limit: Maximum results to return (1-20).
    """
    try:
        validated_input = SearchDocsInput(query=query, incident_id=incident_id, limit=limit)
    except ValidationError as err:
        return json.dumps(
            {
                "error": "Validation error",
                "details": [e["msg"] for e in err.errors()],
                "trust_level": "system_error",
            }
        )

    conn = get_db_connection()
    try:
        output = execute_search_docs(validated_input, conn)
        return output.model_dump_json()
    finally:
        conn.close()


@mcp_server.tool()
def query_security_logs(
    incident_id: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 20,
) -> str:
    """Query synthetic security logs using parameterized filters.

    Args:
        incident_id: Filter by incident ID (e.g. INC-001).
        event_type: Event type filter (e.g. AUTH_FAILED, S3_EXPORT).
        source_ip: Source IP filter (e.g. 198.51.100.42).
        status: Status filter (e.g. SUCCESS, FAILED).
        limit: Maximum log rows to return (1-50).
    """
    try:
        validated_input = QueryLogsInput(
            incident_id=incident_id,
            event_type=event_type,
            source_ip=source_ip,
            status=status,
            limit=limit,
        )
    except ValidationError as err:
        return json.dumps(
            {
                "error": "Validation error",
                "details": [e["msg"] for e in err.errors()],
                "trust_level": "system_error",
            }
        )

    conn = get_db_connection()
    try:
        output = execute_query_logs(validated_input, conn)
        return output.model_dump_json()
    finally:
        conn.close()


@mcp_server.tool()
def get_incident_details(incident_id: str) -> str:
    """Retrieve approved details and status for a single incident.

    Args:
        incident_id: Validated incident ID matching pattern INC-XXX (e.g. INC-001).
    """
    try:
        validated_input = IncidentDetailsInput(incident_id=incident_id)
    except ValidationError as err:
        return json.dumps(
            {
                "error": "Validation error",
                "details": [e["msg"] for e in err.errors()],
                "trust_level": "system_error",
            }
        )

    conn = get_db_connection()
    try:
        output = execute_incident_details(validated_input, conn)
        return output.model_dump_json()
    finally:
        conn.close()


def main():
    """Server entrypoint running over stdio transport."""
    mcp_server.run(transport="stdio")


if __name__ == "__main__":
    main()
