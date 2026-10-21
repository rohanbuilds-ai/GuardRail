"""Evaluation Export utilities for JSON and CSV formats."""

import csv
import io
import json
from guardrail.evaluation.models import EvaluationSuiteResult


def export_suite_to_json(suite: EvaluationSuiteResult) -> str:
    """Export EvaluationSuiteResult as formatted JSON string."""
    return suite.model_dump_json(indent=2)


def export_suite_to_csv(suite: EvaluationSuiteResult) -> str:
    """Export scenario execution results as tabular CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(
        [
            "run_id",
            "scenario_id",
            "scenario_name",
            "category",
            "execution_mode",
            "is_adversarial",
            "has_canary",
            "passed",
            "attack_succeeded",
            "defense_succeeded",
            "is_false_block",
            "canary_leaked",
            "citations_grounded",
            "tool_executions_count",
            "execution_time_ms",
            "outcome_note",
            "error_message",
        ]
    )

    for res in suite.scenario_results:
        writer.writerow(
            [
                suite.run_id,
                res.scenario_id,
                res.scenario_name,
                res.category.value if hasattr(res.category, "value") else str(res.category),
                res.execution_mode,
                res.is_adversarial,
                res.has_canary,
                res.passed,
                res.attack_succeeded,
                res.defense_succeeded,
                res.is_false_block,
                res.canary_leaked,
                res.citations_grounded,
                res.tool_executions_count,
                res.execution_time_ms,
                res.outcome_note,
                res.error_message or "",
            ]
        )

    return output.getvalue()
