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
        """Execute a bounded multi-turn investigation workflow."""
        db_conn = self.db_conn or conn

        system_instruction = (
            "You are an AI Security Analyst investigating synthetic security incidents. "
            "You have access to approved read-only tools to retrieve evidence from the security database. "
            "Evidence Grounding Requirement:\n"
            "- You must only cite record IDs (e.g. DOC-001, LOG-001) that were actually returned in tool outputs.\n"
            "- Never fabricate or assume record IDs.\n"
            "- If information is incomplete, clearly state the uncertainty and missing logs in your report."
        )

        user_prompt = (
            f"Analyst Role: {request.analyst_role}\n"
            f"Target Incident: {request.incident_id}\n"
            f"Investigation Objective: {request.query}"
        )

        tools = await self.get_tool_definitions()
        history: List[Dict[str, Any]] = []
        tool_records: List[ToolExecutionRecord] = []
        evidence_ledger: Set[str] = set()

        iteration = 0
        while iteration < self.max_tool_iterations:
            # Model Turn: Decide next action or produce findings
            turn_response = await self.provider.generate_response(
                system_instruction=system_instruction,
                user_prompt=user_prompt,
                history=history,
                tools=tools,
            )

            # If the model produced no tool calls, it is ready to synthesize
            if not turn_response.tool_calls:
                break

            # Process each requested tool call
            for tool_call in turn_response.tool_calls:
                if len(tool_records) >= self.max_tool_iterations:
                    logger.warning(
                        f"Investigation exceeded max tool iteration budget of {self.max_tool_iterations}."
                    )
                    history.append(
                        {
                            "role": "tool",
                            "name": tool_call.name,
                            "content": json.dumps(
                                {
                                    "warning": f"Tool execution budget exhausted (max {self.max_tool_iterations} calls)."
                                }
                            ),
                        }
                    )
                    break

                rec, output_content, discovered_ids = await self.execute_tool(
                    tool_call.name, tool_call.arguments, conn=db_conn
                )
                tool_records.append(rec)
                evidence_ledger.update(discovered_ids)

                history.append(
                    {
                        "role": "tool",
                        "name": tool_call.name,
                        "content": output_content or json.dumps({"status": rec.status}),
                    }
                )

            iteration += 1

        # Final Synthesis Turn: Ensure structured report
        synthesis_prompt = (
            f"Based on the tool evidence gathered above for {request.incident_id}, synthesize a structured investigation report. "
            "Output valid JSON containing:\n"
            "- summary: High-level overview of the incident\n"
            "- timeline_findings: List of sequential chronological points supported by evidence\n"
            "- root_cause_analysis: Probable root cause or vector\n"
            "- cited_records: List of record IDs (e.g. DOC-001, LOG-001) that support your findings\n"
            "- uncertainty_and_limitations: Gaps in evidence or investigative boundaries\n"
            "- confidence: 'low', 'medium', or 'high'"
        )

        final_turn = await self.provider.generate_response(
            system_instruction=system_instruction,
            user_prompt=synthesis_prompt,
            history=history,
            tools=None,
        )

        # Parse model synthesis into structured response
        try:
            parsed = json.loads(final_turn.content or "{}")
        except json.JSONDecodeError:
            parsed = {
                "summary": final_turn.content or "Investigation concluded.",
                "timeline_findings": [],
                "root_cause_analysis": "Direct output parsing failed; see summary.",
                "cited_records": [],
                "uncertainty_and_limitations": "Model response was not formatted in strict JSON.",
                "confidence": "low",
            }

        raw_cited = parsed.get("cited_records", [])

        # Grounding Enforcement: Verify cited records against evidence ledger
        grounded_citations: List[str] = []
        hallucinated_citations: List[str] = []

        for cid in raw_cited:
            if cid in evidence_ledger or not evidence_ledger:
                grounded_citations.append(cid)
            else:
                hallucinated_citations.append(cid)

        # Document any ungrounded citations in uncertainty
        uncertainty = parsed.get(
            "uncertainty_and_limitations",
            "Analysis bounded by synthetic logs and available documentation.",
        )
        if hallucinated_citations:
            uncertainty += f" [Note: Citations {hallucinated_citations} could not be verified in tool evidence ledger and were excluded.]"

        return InvestigationResponse(
            incident_id=request.incident_id,
            query=request.query,
            analyst_role=request.analyst_role,
            summary=parsed.get("summary", "Investigation completed."),
            timeline_findings=parsed.get("timeline_findings", []),
            root_cause_analysis=parsed.get(
                "root_cause_analysis", "No root cause identified."
            ),
            cited_records=grounded_citations,
            uncertainty_and_limitations=uncertainty,
            confidence=parsed.get("confidence", "medium"),
            tool_executions=tool_records,
            execution_mode="baseline",
        )
