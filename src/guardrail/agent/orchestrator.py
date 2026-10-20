"""Multi-Turn Agent Orchestrator for GuardRail.

Coordinates iterative evidence retrieval using the MCP client,
validates arguments independently in trusted code, bounds resource consumption,
and guarantees evidence grounding (cross-referencing cited IDs against an evidence ledger).
"""

import json
import logging
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set
from guardrail.agent.baseline import BaselineAgent
from guardrail.agent.hardened import HardenedAgent
from guardrail.config import settings
from guardrail.mcp.client import MCPClientManager
from guardrail.providers.base import BaseLLMProvider
from guardrail.providers.factory import get_llm_provider
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

logger = logging.getLogger("guardrail.agent.orchestrator")

PERMITTED_TOOLS = {
    "search_incident_documents",
    "query_security_logs",
    "get_incident_details",
}


class AgentOrchestrator:
    """Manages multi-turn reasoning loops, tool invocation via MCP, and report synthesis."""

    def __init__(
        self,
        provider: Optional[BaseLLMProvider] = None,
        mcp_client: Optional[MCPClientManager] = None,
        max_tool_iterations: Optional[int] = None,
        db_conn: Optional[sqlite3.Connection] = None,
    ):
        self.provider = provider or get_llm_provider()
        self.mcp_client = mcp_client or MCPClientManager()
        self.max_tool_iterations = (
            max_tool_iterations
            if max_tool_iterations is not None
            else settings.max_tool_iterations
        )
        self.db_conn = db_conn

    async def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Discover tools from MCP server, falling back to static schemas if MCP is unreachable."""
        try:
            mcp_tools = await self.mcp_client.list_tools()
            if mcp_tools:
                return mcp_tools
        except Exception as exc:
            logger.warning(f"Could not discover tools from MCP server ({exc}). Using internal definitions.")

        from guardrail.agent.investigator import TOOL_DEFINITIONS
        return TOOL_DEFINITIONS

    async def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        conn: Optional[sqlite3.Connection] = None,
    ) -> tuple[ToolExecutionRecord, str, Set[str]]:
        """Validate and execute a tool via MCP client or local connection.

        Returns:
            Tuple of (ToolExecutionRecord, json_output_string, set_of_discovered_record_ids)
        """
        discovered_ids: Set[str] = set()

        # Step 1: Tool Name Allowlisting
        if tool_name not in PERMITTED_TOOLS:
            err_msg = f"Tool '{tool_name}' is not in the approved security tool allowlist."
            rec = ToolExecutionRecord(
                tool_name=tool_name,
                arguments=arguments,
                result_summary="Unauthorized tool requested",
                status="error",
                error_message=err_msg,
            )
            return rec, json.dumps({"error": err_msg}), discovered_ids

        # Step 2: Independent Argument Validation
        try:
            if tool_name == "search_incident_documents":
                validated_args = SearchDocsInput(**arguments).model_dump(exclude_none=True)
            elif tool_name == "query_security_logs":
                validated_args = QueryLogsInput(**arguments).model_dump(exclude_none=True)
            elif tool_name == "get_incident_details":
                validated_args = IncidentDetailsInput(**arguments).model_dump(exclude_none=True)
            else:
                validated_args = arguments
        except Exception as val_err:
            err_msg = f"Argument validation failed: {val_err}"
            rec = ToolExecutionRecord(
                tool_name=tool_name,
                arguments=arguments,
                result_summary="Malformed parameters",
                status="error",
                error_message=err_msg,
            )
            return rec, json.dumps({"error": err_msg}), discovered_ids

        # Step 3: Tool Execution via MCP client (or local DB if connection provided)
        if conn is not None and not self.mcp_client:
            # Direct in-process execution against provided DB connection (useful for in-memory tests)
            if tool_name == "search_incident_documents":
                res = search_incident_documents(SearchDocsInput(**validated_args), conn)
                raw_json = res.model_dump_json()
                rec_count = res.total_found
                discovered_ids.update(doc.id for doc in res.documents)
            elif tool_name == "query_security_logs":
                res = query_security_logs(QueryLogsInput(**validated_args), conn)
                raw_json = res.model_dump_json()
                rec_count = res.total_found
                discovered_ids.update(log.id for log in res.logs)
            else:
                res = get_incident_details(IncidentDetailsInput(**validated_args), conn)
                raw_json = res.model_dump_json()
                rec_count = 1 if res.found else 0
                if res.found and res.incident:
                    discovered_ids.add(res.incident.id)

            rec = ToolExecutionRecord(
                tool_name=tool_name,
                arguments=arguments,
                result_summary=f"Executed locally ({rec_count} records)",
                record_count=rec_count,
                status="success",
            )
            return rec, raw_json, discovered_ids

        # Standard execution via MCP Client over stdio
        mcp_res = await self.mcp_client.call_tool(tool_name, validated_args)

        # Extract record IDs from MCP output to prevent hallucinations
        if mcp_res.content:
            found_docs = re.findall(r"DOC-\d{3}", mcp_res.content)
            found_logs = re.findall(r"LOG-\d{3}", mcp_res.content)
            discovered_ids.update(found_docs)
            discovered_ids.update(found_logs)

        rec = ToolExecutionRecord(
            tool_name=tool_name,
            arguments=arguments,
            result_summary=f"MCP execution ({mcp_res.record_count} records)"
            if mcp_res.status == "success"
            else (mcp_res.error_message or "Error"),
            record_count=mcp_res.record_count,
            status="success" if mcp_res.status == "success" else "error",
            error_message=mcp_res.error_message,
        )

        return rec, mcp_res.content, discovered_ids

    async def investigate(
        self,
        request: InvestigationRequest,
        conn: Optional[sqlite3.Connection] = None,
    ) -> InvestigationResponse:
        """Execute investigation routing cleanly to BaselineAgent or HardenedAgent."""
        if request.execution_mode == "baseline":
            baseline_agent = BaselineAgent(
                provider=self.provider,
                mcp_client=self.mcp_client,
                max_tool_iterations=self.max_tool_iterations,
                db_conn=self.db_conn,
            )
            return await baseline_agent.investigate(request, conn)

        # Default to HardenedAgent
        hardened_agent = HardenedAgent(
            provider=self.provider,
            mcp_client=self.mcp_client,
            max_tool_iterations=self.max_tool_iterations,
            db_conn=self.db_conn,
        )
        return await hardened_agent.investigate(request, conn)
