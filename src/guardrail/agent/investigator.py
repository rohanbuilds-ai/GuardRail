"""Agent Investigator supporting 3 MCP Tools.

Design Decision:
In Phase 2, we expand tool capabilities to all 3 core investigation tools:
1. search_incident_documents
2. query_security_logs
3. get_incident_details

The investigator validates arguments, records detailed audit logs, and handles
unknown tools or validation errors safely without crashing.
"""

import json
import sqlite3
from typing import Any, Dict, List, Optional
from guardrail.config import settings
from guardrail.mcp.client import MCPClientManager
from guardrail.providers.base import BaseLLMProvider
from guardrail.providers.mock_provider import MockLLMProvider
from guardrail.storage.models import (
    InvestigationRequest,
    InvestigationResponse,
    ToolExecutionRecord,
)
from guardrail.tools.incident_details import (
    IncidentDetailsInput,
    get_incident_details,
)
from guardrail.tools.query_logs import (
    QueryLogsInput,
    query_security_logs,
)
from guardrail.tools.search_docs import (
    SearchDocsInput,
    search_incident_documents,
)


TOOL_DEFINITIONS = [
    {
        "name": "search_incident_documents",
        "description": "Search approved synthetic incident documentation and triage notes.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term or keyword"},
                "incident_id": {
                    "type": "string",
                    "description": "Optional incident ID filter (e.g. INC-001)",
                },
                "limit": {"type": "integer", "description": "Max documents to return (1-20)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "query_security_logs",
        "description": "Query synthetic security logs using parameterized filters.",
        "parameters": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "Filter by incident ID (e.g. INC-001)"},
                "event_type": {"type": "string", "description": "Event type filter (e.g. AUTH_FAILED)"},
                "source_ip": {"type": "string", "description": "Source IP address filter"},
                "status": {"type": "string", "description": "Event status filter (e.g. SUCCESS, FAILED)"},
                "limit": {"type": "integer", "description": "Max logs to return (1-50)"},
            },
        },
    },
    {
        "name": "get_incident_details",
        "description": "Retrieve approved metadata and status for a single incident.",
        "parameters": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "Target incident ID (e.g. INC-001)"},
            },
            "required": ["incident_id"],
        },
    },
]


class AgentInvestigator:
    """Coordinates tool execution and provider synthesis for incident investigation."""

    def __init__(
        self,
        provider: Optional[BaseLLMProvider] = None,
        db_conn: Optional[sqlite3.Connection] = None,
        mcp_client: Optional[MCPClientManager] = None,
    ):
        self.provider = provider or MockLLMProvider()
        self.db_conn = db_conn
        self.mcp_client = mcp_client

    async def execute_tool_locally(
        self, tool_name: str, arguments: Dict[str, Any], conn: sqlite3.Connection
    ) -> ToolExecutionRecord:
        """Execute a tool locally using the validated domain functions."""
        try:
            if tool_name == "search_incident_documents":
                validated_args = SearchDocsInput(**arguments)
                result = search_incident_documents(validated_args, conn=conn)
                return ToolExecutionRecord(
                    tool_name=tool_name,
                    arguments=arguments,
                    result_summary=f"Found {result.total_found} matching documents",
                    record_count=result.total_found,
                    status="success",
                )

            elif tool_name == "query_security_logs":
                validated_args = QueryLogsInput(**arguments)
                result = query_security_logs(validated_args, conn=conn)
                return ToolExecutionRecord(
                    tool_name=tool_name,
                    arguments=arguments,
                    result_summary=f"Retrieved {result.total_found} security logs",
                    record_count=result.total_found,
                    status="success",
                )

            elif tool_name == "get_incident_details":
                validated_args = IncidentDetailsInput(**arguments)
                result = get_incident_details(validated_args, conn=conn)
                return ToolExecutionRecord(
                    tool_name=tool_name,
                    arguments=arguments,
                    result_summary=result.message or "Incident details retrieved",
                    record_count=1 if result.found else 0,
                    status="success" if result.found else "error",
                    error_message=None if result.found else result.message,
                )

            else:
                return ToolExecutionRecord(
                    tool_name=tool_name,
                    arguments=arguments,
                    result_summary="Unknown tool requested",
                    status="error",
                    error_message=f"Tool '{tool_name}' is not recognized or permitted.",
                )

        except Exception as exc:
            return ToolExecutionRecord(
                tool_name=tool_name,
                arguments=arguments,
                result_summary="Validation or execution failed",
                status="error",
                error_message=str(exc),
            )

    async def investigate(
        self, request: InvestigationRequest, conn: sqlite3.Connection
    ) -> InvestigationResponse:
        """Run an end-to-end investigation workflow."""
        db_connection = self.db_conn or conn

        system_instruction = (
            "You are an AI Security Analyst investigating synthetic security incidents. "
            "You have access to approved read-only tools to retrieve evidence. "
            "Always cite the exact record IDs (e.g. DOC-001, LOG-001) that justify your conclusions."
        )

        user_prompt = (
            f"Analyst Role: {request.analyst_role}\n"
            f"Target Incident: {request.incident_id}\n"
            f"Investigation Task: {request.query}"
        )

        history: List[Dict[str, Any]] = []
        tool_records: List[ToolExecutionRecord] = []

        # Turn 1: Ask model for reasoning / tool call
        first_turn = await self.provider.generate_response(
            system_instruction=system_instruction,
            user_prompt=user_prompt,
            history=history,
            tools=TOOL_DEFINITIONS,
        )

        # Process any tool calls requested by the model
        for tool_call in first_turn.tool_calls:
            if self.mcp_client:
                # Execute via standalone MCP client over stdio
                mcp_res = await self.mcp_client.call_tool(tool_call.name, tool_call.arguments)
                rec = ToolExecutionRecord(
                    tool_name=mcp_res.tool_name,
                    arguments=mcp_res.arguments,
                    result_summary=f"MCP call completed ({mcp_res.record_count} records)" if mcp_res.status == "success" else (mcp_res.error_message or "Error"),
                    record_count=mcp_res.record_count,
                    status="success" if mcp_res.status == "success" else "error",
                    error_message=mcp_res.error_message,
                )
                tool_records.append(rec)
                history.append(
                    {
                        "role": "tool",
                        "name": tool_call.name,
                        "content": mcp_res.content or json.dumps({"error": mcp_res.error_message}),
                    }
                )
            else:
                # Execute locally against connection
                rec = await self.execute_tool_locally(tool_call.name, tool_call.arguments, db_connection)
                tool_records.append(rec)

                # Fetch structured content for LLM history
                if rec.status == "success":
                    if tool_call.name == "search_incident_documents":
                        out = search_incident_documents(SearchDocsInput(**tool_call.arguments), db_connection)
                        content = out.model_dump_json()
                    elif tool_call.name == "query_security_logs":
                        out = query_security_logs(QueryLogsInput(**tool_call.arguments), db_connection)
                        content = out.model_dump_json()
                    elif tool_call.name == "get_incident_details":
                        out = get_incident_details(IncidentDetailsInput(**tool_call.arguments), db_connection)
                        content = out.model_dump_json()
                    else:
                        content = json.dumps({"status": "unknown"})
                else:
                    content = json.dumps({"error": rec.error_message})

                history.append(
                    {
                        "role": "tool",
                        "name": tool_call.name,
                        "content": content,
                    }
                )

        # Turn 2: Model synthesizes final structured response from tool evidence
        final_turn = await self.provider.generate_response(
            system_instruction=system_instruction,
            user_prompt=user_prompt,
            history=history,
            tools=None,
        )

        # Parse model synthesis into structured response
        try:
            parsed_content = json.loads(final_turn.content or "{}")
        except json.JSONDecodeError:
            parsed_content = {
                "summary": final_turn.content or "No summary generated.",
                "timeline_findings": [],
                "root_cause_analysis": "Unable to parse structured output from model.",
                "cited_records": [],
                "confidence": "low",
            }

        return InvestigationResponse(
            incident_id=request.incident_id,
            query=request.query,
            analyst_role=request.analyst_role,
            summary=parsed_content.get("summary", "Investigation completed."),
            timeline_findings=parsed_content.get("timeline_findings", []),
            root_cause_analysis=parsed_content.get(
                "root_cause_analysis", "No root cause identified."
            ),
            cited_records=parsed_content.get("cited_records", []),
            confidence=parsed_content.get("confidence", "medium"),
            tool_executions=tool_records,
            execution_mode="baseline",
        )
