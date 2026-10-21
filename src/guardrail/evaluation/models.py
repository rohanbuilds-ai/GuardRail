"""Data models and schemas for the GuardRail Red-Team Evaluation Engine.

Design Decision:
Every scenario is explicitly versioned, categorized into one of the 10 threat categories,
and specifies exact pass/fail security criteria. Metric items maintain explicit
numerator, denominator, and computed percentages to ensure 100% mathematical transparency.
"""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    """The 10 evaluation threat categories defined in the GuardRail master specification."""

    DIRECT_INJECTION = "direct_prompt_injection"
    INDIRECT_INJECTION = "indirect_prompt_injection"
    UNAUTHORIZED_TOOLS = "unauthorized_tool_use"
    ARGUMENT_VALIDATION = "argument_validation"
    CANARY_DISCLOSURE = "synthetic_canary_disclosure"
    DATA_ISOLATION_RBAC = "data_isolation_rbac"
    UNSAFE_RETRIEVED_CONTENT = "unsafe_retrieved_content"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    OUTPUT_CITATION_VALIDATION = "output_validation_citations"
    BENIGN_REGRESSION = "benign_investigation_regression"


class EvaluationScenario(BaseModel):
    """Structured, reproducible definition of a red-team evaluation scenario."""

    id: str = Field(..., description="Unique scenario ID, e.g. SCN-DIR-01")
    category: ThreatCategory = Field(..., description="Threat category")
    version: str = Field(default="1.0", description="Scenario version")
    name: str = Field(..., description="Short descriptive name")
    description: str = Field(..., description="Detailed description of attack objective or test purpose")
    incident_id: str = Field(..., description="Target incident ID (e.g. INC-001, INC-002, INC-003)")
    query: str = Field(..., description="Prompt or adversarial input submitted to the agent")
    analyst_role: Literal["tier_1", "tier_2", "lead"] = Field(
        default="tier_1", description="Analyst permission context"
    )
    is_adversarial: bool = Field(
        ..., description="True if scenario is an attack; False if benign regression scenario"
    )
    has_canary: bool = Field(
        default=False, description="True if scenario involves synthetic canary token exposure"
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        default="medium", description="Threat severity level"
    )
    expected_security_property: str = Field(
        ..., description="Expected security behavior or defense rule under evaluation"
    )


class MetricItem(BaseModel):
    """Represents a calculated metric with explicit numerator and denominator."""

    numerator: int
    denominator: int
    percentage: float

    @classmethod
    def calculate(cls, numerator: int, denominator: int) -> "MetricItem":
        """Calculate percentage safely, returning 0.0% if denominator is zero."""
        pct = round((numerator / denominator * 100.0), 2) if denominator > 0 else 0.0
        return cls(numerator=numerator, denominator=denominator, percentage=pct)


class EvaluationMetrics(BaseModel):
    """Complete collection of red-team evaluation metrics."""

    attack_success_rate: MetricItem
    defense_success_rate: MetricItem
    false_block_rate: MetricItem
    canary_leakage_rate: MetricItem
    citation_integrity_rate: MetricItem
    total_scenarios_evaluated: int


class ScenarioExecutionResult(BaseModel):
    """Outcome of running a single scenario in a specific defense mode."""

    scenario_id: str
    scenario_name: str
    category: ThreatCategory
    execution_mode: Literal["baseline", "hardened"]
    is_adversarial: bool
    has_canary: bool = False
    passed: bool
    attack_succeeded: bool
    defense_succeeded: bool
    is_false_block: bool
    canary_leaked: bool
    citations_grounded: bool
    summary: str
    security_alerts: List[str] = Field(default_factory=list)
    cited_records: List[str] = Field(default_factory=list)
    tool_executions_count: int = 0
    execution_time_ms: float = 0.0
    outcome_note: str
    error_message: Optional[str] = None


class EvaluationSuiteResult(BaseModel):
    """Complete evaluation report comparing Baseline and Hardened execution."""

    run_id: str
    timestamp: str
    provider: str
    total_scenarios: int
    baseline_metrics: EvaluationMetrics
    hardened_metrics: EvaluationMetrics
    scenario_results: List[ScenarioExecutionResult]
