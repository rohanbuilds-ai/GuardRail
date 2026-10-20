"""Deterministic Mock LLM Provider for GuardRail.

Purpose:
Provides 100% predictable, offline responses for unit tests, CI pipelines,
and local evaluation runs without requiring API keys or incurring token costs.
Emulates realistic agent reasoning loops (deciding to call tools, then synthesizing
findings from tool outputs).
"""

import json
import re
from typing import Any, Dict, List, Optional
from guardrail.providers.base import BaseLLMProvider, ProviderResponse, ToolCallRequest


class MockLLMProvider(BaseLLMProvider):
    """Deterministic, rule-based provider for testing and offline development."""

    def __init__(self, model_name: str = "mock-deterministic-v1"):
        self.model_name = model_name

    async def generate_response(
        self,
        system_instruction: str,
        user_prompt: str,
        history: Optional[List[Dict[str, Any]]] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ProviderResponse:
        history = history or []

        # Check if history already contains tool execution results
        has_tool_results = any(msg.get("role") == "tool" for msg in history)

        # Step 1: If tools are available and we haven't executed a tool yet, decide to call a tool
        if tools and not has_tool_results:
            # Extract incident ID if present in user prompt (e.g. INC-001)
            inc_match = re.search(r"INC-\d{3}", user_prompt)
            target_inc = inc_match.group(0) if inc_match else "INC-001"

            # Determine query keyword
            query_kw = "VPN" if "VPN" in user_prompt or "INC-001" in user_prompt else "S3"

            return ProviderResponse(
                content=None,
                tool_calls=[
                    ToolCallRequest(
                        id="call_mock_001",
                        name="search_incident_documents",
                        arguments={"query": query_kw, "incident_id": target_inc, "limit": 5},
                    )
                ],
                finish_reason="tool_calls",
                model_name=self.model_name,
                usage={"prompt_tokens": 120, "completion_tokens": 25},
            )

        # Step 2: If tool results exist in history, synthesize structured investigation report
        tool_outputs = [msg.get("content", "") for msg in history if msg.get("role") == "tool"]
        tool_content_combined = " ".join(tool_outputs)

        # Extract cited doc IDs
        cited_docs = list(set(re.findall(r"DOC-\d{3}", tool_content_combined)))
        if not cited_docs:
            cited_docs = ["DOC-001"]

        # Synthesize realistic findings based on the incident
        if "INC-002" in user_prompt or "S3" in tool_content_combined:
            response_json = {
                "summary": "Investigation into suspicious S3 outbound data transfer anomaly (INC-002).",
                "timeline_findings": [
                    "CloudWatch alarm triggered on bucket 'corp-analytics-staging-prod' at 14:00 UTC.",
                    "14.2 GB of parquet data was exported to external IP 203.0.113.88.",
                    "IAM role AnalyticsSyncWorker was utilized from EC2 instance i-0abcdef1234567890.",
                ],
                "root_cause_analysis": (
                    "Scheduled backup automation was reconfigured with an external destination IP address. "
                    "Further investigation into the IAM credential modifier is required."
                ),
                "cited_records": cited_docs,
                "confidence": "high",
            }
        else:
            response_json = {
                "summary": "Investigation into automated credential stuffing against GlobalProtect VPN (INC-001).",
                "timeline_findings": [
                    "High volume authentication failures detected originating from IP 198.51.100.42.",
                    "Over 450 attempts within 10 minutes targeted accounts matching 'dev-*'.",
                    "Target account 'dev-svc-backup' was locked out after 12 consecutive attempts.",
                    "No successful compromise was observed; perimeter WAF rate-limiting engaged.",
                ],
                "root_cause_analysis": (
                    "External botnet (Hydra automated spray) targeting standard service account names. "
                    "Perimeter IP blocking and mandatory password rotation implemented."
                ),
                "cited_records": cited_docs,
                "confidence": "high",
            }

        return ProviderResponse(
            content=json.dumps(response_json),
            tool_calls=[],
            finish_reason="stop",
            model_name=self.model_name,
            usage={"prompt_tokens": 280, "completion_tokens": 140},
        )
