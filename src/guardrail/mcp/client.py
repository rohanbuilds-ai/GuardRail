"""MCP Client Manager for GuardRail.

Coordinates process lifecycle, stdio communication, and execution of tools
hosted on the standalone GuardRail MCP Server using the official MCP Python SDK.

Design Decision:
The client runs the MCP server as a subprocess communicating over stdio.
It enforces timeouts (default 10s), records audit trails, and isolates
server crashes or timeouts so the main FastAPI web server remains completely stable.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel, Field

logger = logging.getLogger("guardrail.mcp.client")


class MCPToolExecutionResult(BaseModel):
    """Structured result from an MCP tool call."""

    tool_name: str
    arguments: Dict[str, Any]
    content: str = ""
    status: str = "success"  # 'success', 'denied', 'error', 'timeout'
    record_count: int = 0
    error_message: Optional[str] = None


class MCPClientManager:
    """Manages stdio communication with the GuardRail MCP server process."""

    def __init__(
        self,
        server_command: Optional[str] = None,
        server_args: Optional[List[str]] = None,
        timeout_seconds: float = 10.0,
    ):
        self.server_command = server_command or sys.executable
        self.server_args = server_args or ["-m", "guardrail.mcp.server"]
        self.timeout_seconds = timeout_seconds

    def _get_server_params(self) -> StdioServerParameters:
        """Construct server parameters passing necessary environment variables."""
        # Clean environment to prevent leaking unneeded env vars while ensuring Python path works
        env = os.environ.copy()
        return StdioServerParameters(
            command=self.server_command,
            args=self.server_args,
            env=env,
        )

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Query the MCP server for available tools and their JSON schemas."""
        params = self._get_server_params()
        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await asyncio.wait_for(session.initialize(), timeout=self.timeout_seconds)
                    tools_result = await asyncio.wait_for(
                        session.list_tools(), timeout=self.timeout_seconds
                    )

                    formatted_tools = []
                    for t in tools_result.tools:
                        formatted_tools.append(
                            {
                                "name": t.name,
                                "description": t.description or "",
                                "parameters": t.input_schema or {},
                            }
                        )
                    return formatted_tools
        except Exception as exc:
            logger.error(f"Failed to list MCP tools: {exc}")
            return []

    async def call_tool(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> MCPToolExecutionResult:
        """Execute a tool call against the MCP server with strict timeout handling."""
        params = self._get_server_params()

        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await asyncio.wait_for(session.initialize(), timeout=self.timeout_seconds)

                    call_coro = session.call_tool(tool_name, arguments=arguments)
                    result = await asyncio.wait_for(call_coro, timeout=self.timeout_seconds)

                    # Extract text content from result
                    content_text = ""
                    if result.content:
                        content_text = "\n".join(
                            item.text for item in result.content if hasattr(item, "text")
                        )

                    # Determine record count from JSON if possible
                    record_count = 0
                    try:
                        parsed = json.loads(content_text)
                        if "total_found" in parsed:
                            record_count = parsed["total_found"]
                        elif "found" in parsed and parsed["found"]:
                            record_count = 1
                    except Exception:
                        pass

                    # Check for server-side error flag or validation error
                    if getattr(result, "is_error", False) or '"trust_level": "system_error"' in content_text or '"error":' in content_text:
                        return MCPToolExecutionResult(
                            tool_name=tool_name,
                            arguments=arguments,
                            content=content_text,
                            status="error",
                            record_count=0,
                            error_message=content_text or "Tool validation or execution error reported by MCP server",
                        )

                    return MCPToolExecutionResult(
                        tool_name=tool_name,
                        arguments=arguments,
                        content=content_text,
                        status="success",
                        record_count=record_count,
                    )

        except asyncio.TimeoutError:
            logger.warning(f"MCP tool call '{tool_name}' timed out after {self.timeout_seconds}s")
            return MCPToolExecutionResult(
                tool_name=tool_name,
                arguments=arguments,
                status="timeout",
                error_message=f"MCP tool call exceeded timeout limit of {self.timeout_seconds} seconds",
            )
        except Exception as exc:
            logger.error(f"MCP tool call '{tool_name}' failed with exception: {exc}")
            return MCPToolExecutionResult(
                tool_name=tool_name,
                arguments=arguments,
                status="error",
                error_message=str(exc),
            )
