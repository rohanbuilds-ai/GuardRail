"""Domain models and schemas for GuardRail.

Design Decision:
We use Pydantic models for both internal business entities and API request/response
contracts. This guarantees strong typing, automatic schema validation, and safe
serialization between database rows, agent components, and API callers.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class IncidentRecord(BaseModel):
    """Represents a synthetic security incident in the system."""

    id: str = Field(..., description="Unique incident identifier (e.g. INC-001)")
    title: str = Field(..., description="Brief title describing the incident")
    severity: Literal["low", "medium", "high", "critical"] = Field(
        ..., description="Incident severity level"
    )
    status: Literal["open", "investigating", "contained", "closed"] = Field(
        default="investigating", description="Current lifecycle state"
    )
    description: str = Field(..., description="High-level description of the incident")
    sensitivity_tier: Literal["tier_1", "tier_2", "tier_3"] = Field(
        default="tier_1",
        description="Analyst authorization tier required to inspect this incident",
    )
    created_at: str = Field(..., description="ISO 8601 creation timestamp")
    assigned_analyst: str = Field(default="secops-auto")


class IncidentDocument(BaseModel):
    """Approved synthetic incident documentation, notes, or runbooks."""

    id: str = Field(..., description="Unique document ID (e.g. DOC-001)")
    incident_id: str = Field(..., description="Associated incident ID")
    title: str = Field(..., description="Document title")
    doc_type: Literal["initial_triage", "analyst_notes", "forensics_report", "runbook"] = (
        Field(..., description="Category of document")
    )
    content: str = Field(..., description="Text content of the document")
    classification: Literal["public", "internal", "restricted"] = Field(
        default="internal", description="Document access classification"
    )
    author: str = Field(default="system")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")


class SecurityLogRecord(BaseModel):
    """Represents a synthetic security log entry (auth, network, access)."""

    id: str = Field(..., description="Unique log ID (e.g. LOG-001)")
    incident_id: str = Field(..., description="Associated incident ID")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    event_type: str = Field(..., description="Type of event (e.g. AUTH_FAILED)")
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    user_id: str = Field(..., description="User identity or service account")
    action: str = Field(..., description="Security action taken")
    status: str = Field(..., description="Status (e.g. SUCCESS, FAILED)")
    details: str = Field(..., description="Technical event details")


class ToolExecutionRecord(BaseModel):
    """Audit log of a single tool invocation made during an investigation."""

    tool_name: str
    arguments: Dict[str, Any]
    result_summary: str
    record_count: int = 0
    status: Literal["success", "denied", "error"] = "success"
    error_message: Optional[str] = None


class InvestigationRequest(BaseModel):
    """User/Analyst request to investigate an incident."""

    incident_id: str = Field(..., description="Target incident ID (e.g. INC-001)")
    query: str = Field(
        ...,
        min_length=3,
        max_length=500,
        description="Investigation question or analytical task",
    )
    analyst_role: Literal["tier_1", "tier_2", "lead"] = Field(
        default="tier_1", description="Analyst permission level"
    )
    execution_mode: Literal["baseline", "hardened"] = Field(
        default="hardened", description="Agent defense mode: baseline or hardened"
    )


class InvestigationResponse(BaseModel):
    """Structured response synthesized by the AI agent."""

    incident_id: str
    query: str
    analyst_role: str
    summary: str
    timeline_findings: List[str] = Field(default_factory=list)
    root_cause_analysis: str
    cited_records: List[str] = Field(
        default_factory=list,
        description="Explicit record IDs (e.g. DOC-001) supporting factual claims",
    )
    uncertainty_and_limitations: Optional[str] = Field(
        default="Analysis bounded by synthetic logs and available documentation.",
        description="Identified uncertainties, data gaps, or investigative limitations",
    )
    confidence: Literal["low", "medium", "high"] = "medium"
    tool_executions: List[ToolExecutionRecord] = Field(default_factory=list)
    execution_mode: Literal["baseline", "hardened"] = "hardened"
    security_alerts: List[str] = Field(
        default_factory=list, description="Security policy warnings or canary redaction alerts"
    )
