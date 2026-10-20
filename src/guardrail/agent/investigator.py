"""Minimal Vertical Slice Agent Investigator.

Design Decision:
In Phase 1, we implement the essential agent loop:
User Query -> LLM Reasoning -> Tool Call Request -> Execution -> Synthesis -> Response.
This validates the full end-to-end flow before adding the formal MCP transport
and dual baseline/hardened security policies in subsequent phases.
"""

import json
import sqlite3
from typing import Any, Dict, List, Optional
from guardrail.config import settings
from guardrail.providers.base import BaseLLMProvider
from guardrail.providers.mock_provider import MockLLMProvider
from guardrail.storage.models import (
    InvestigationRequest,
    InvestigationResponse,
    ToolExecutionRecord,
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
    }
]


class AgentInvestigator:
    """Coordinates tool execution and provider synthesis for incident investigation."""

    def __init__(
        self,
        provider: Optional[BaseLLMProvider] = None,
        db_conn: Optional[sqlite3.Connection] = None,
    ):
        self.provider = provider or MockLLMProvider()
        self.db_conn = db_conn

    async def investigate(
        self, request: InvestigationRequest, conn: sqlite3.Connection
    ) -> InvestigationResponse:
        """Run an end-to-end investigation workflow."""
        db_connection = self.db_conn or conn

        system_instruction = (
            "You are an AI Security Analyst investigating synthetic security incidents. "
            "You have access to approved read-only tools to retrieve evidence. "
            "Always cite the exact record IDs (e.g. DOC-001) that justify your conclusions."
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
            if tool_call.name == "search_incident_documents":
                try:
                    # Validate arguments through Pydantic
                    validated_args = SearchDocsInput(**tool_call.arguments)
                    result = search_incident_documents(validated_args, conn=db_connection)

                    tool_records.append(
                        ToolExecutionRecord(
                            tool_name=tool_call.name,
                            arguments=tool_call.arguments,
                            result_summary=f"Found {result.total_found} matching documents",
                            record_count=result.total_found,
                            status="success",
                        )
                    )

                    # Feed tool output back to agent history
                    history.append(
                        {
                            "role": "tool",
                            "name": tool_call.name,
                            "content": result.model_dump_json(),
                        }
                    )
                except Exception as exc:
                    tool_records.append(
                        ToolExecutionRecord(
                            tool_name=tool_call.name,
                            arguments=tool_call.arguments,
                            result_summary="Execution failed",
                            status="error",
                            error_message=str(exc),
                        )
                    )
                    history.append(
                        {
                            "role": "tool",
                            "name": tool_call.name,
                            "content": json.dumps({"error": str(exc)}),
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
