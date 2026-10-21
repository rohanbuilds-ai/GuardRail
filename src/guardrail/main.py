"""FastAPI Application Entrypoint for GuardRail.

Endpoints:
- GET  /health                      Health check & runtime telemetry
- GET  /api/incidents               List all seeded synthetic incidents
- GET  /api/incidents/{incident_id} Retrieve specific incident metadata
- POST /api/investigate             Execute agent investigation with tool calls
- GET  /                            Web dashboard UI
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Literal, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field

from guardrail.agent.investigator import AgentInvestigator
from guardrail.agent.orchestrator import AgentOrchestrator
from guardrail.config import PROJECT_ROOT, settings
from guardrail.evaluation import (
    ALL_EVALUATION_SCENARIOS,
    EvaluationRunner,
    EvaluationScenario,
    EvaluationSuiteResult,
    export_suite_to_csv,
    export_suite_to_json,
)
from guardrail.storage.database import (
    get_all_incidents,
    get_db_connection,
    get_incident_by_id,
    init_db,
)
from guardrail.storage.models import (
    IncidentRecord,
    InvestigationRequest,
    InvestigationResponse,
)
from guardrail.storage.seed_data import seed_database


TEMPLATES_DIR = PROJECT_ROOT / "frontend" / "templates"
STATIC_DIR = PROJECT_ROOT / "frontend" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle hook: initialize database and seed synthetic records on startup."""
    # Ensure database tables exist and are populated with deterministic synthetic data
    conn = get_db_connection()
    try:
        init_db(conn)
        seed_database(conn)
    finally:
        conn.close()
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Secure AI Agent & MCP Red-Team Lab API",
    lifespan=lifespan,
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static frontend assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Jinja template engine setup
jinja_env = (
    Environment(loader=FileSystemLoader(str(TEMPLATES_DIR))) if TEMPLATES_DIR.exists() else None
)


@app.get("/health", tags=["System"])
async def health_check():
    """Returns application health, version, active provider, and database status."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM incidents;")
        count = cursor.fetchone()[0]
        db_status = "connected"
    except Exception as exc:
        db_status = f"error: {exc}"
        count = 0
    finally:
        conn.close()

    return {
        "status": "healthy",
        "version": "0.1.0",
        "provider": settings.provider,
        "environment": settings.environment,
        "database": db_status,
        "incident_count": count,
    }


@app.get("/api/incidents", response_model=List[IncidentRecord], tags=["Incidents"])
async def list_incidents():
    """Retrieve all available synthetic security incidents."""
    conn = get_db_connection()
    try:
        incidents = get_all_incidents(conn)
        return incidents
    finally:
        conn.close()


@app.get("/api/incidents/{incident_id}", response_model=IncidentRecord, tags=["Incidents"])
async def get_incident(incident_id: str):
    """Retrieve details for a single incident by its ID."""
    conn = get_db_connection()
    try:
        incident = get_incident_by_id(conn, incident_id)
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found.",
            )
        return incident
    finally:
        conn.close()


@app.post("/api/investigate", response_model=InvestigationResponse, tags=["Investigation"])
async def investigate_incident(request: InvestigationRequest):
    """Submit an investigation prompt to the AI agent."""
    conn = get_db_connection()
    try:
        # Verify incident exists
        incident = get_incident_by_id(conn, request.incident_id)
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{request.incident_id}' not found in database.",
            )

        orchestrator = AgentOrchestrator()
        response = await orchestrator.investigate(request, conn)
        return response
    finally:
        conn.close()


class EvaluationRunRequest(BaseModel):
    """Payload to trigger an evaluation run."""

    scenario_ids: Optional[List[str]] = Field(
        default=None, description="List of scenario IDs to run. Defaults to all 30 scenarios."
    )
    execution_modes: Optional[List[Literal["baseline", "hardened"]]] = Field(
        default=None, description="Execution modes to evaluate. Defaults to ['baseline', 'hardened']."
    )


# In-memory storage for latest evaluation run
_latest_evaluation_result: Optional[EvaluationSuiteResult] = None


@app.get("/api/scenarios", response_model=List[EvaluationScenario], tags=["Evaluation"])
async def list_evaluation_scenarios(
    category: Optional[str] = None,
    is_adversarial: Optional[bool] = None,
):
    """List all available red-team evaluation scenarios with optional category and adversarial filtering."""
    results = ALL_EVALUATION_SCENARIOS
    if category:
        results = [s for s in results if s.category.value == category or s.category == category]
    if is_adversarial is not None:
        results = [s for s in results if s.is_adversarial == is_adversarial]
    return results


@app.post("/api/evaluations/run", response_model=EvaluationSuiteResult, tags=["Evaluation"])
async def run_evaluation_suite(payload: Optional[EvaluationRunRequest] = None):
    """Trigger red-team evaluation run across scenarios in Baseline and Hardened modes."""
    global _latest_evaluation_result

    req = payload or EvaluationRunRequest()
    runner = EvaluationRunner()
    result = await runner.run_suite(
        scenario_ids=req.scenario_ids,
        execution_modes=req.execution_modes,
    )
    _latest_evaluation_result = result
    return result


@app.get("/api/evaluations/latest", response_model=EvaluationSuiteResult, tags=["Evaluation"])
async def get_latest_evaluation():
    """Retrieve the most recent evaluation suite results."""
    global _latest_evaluation_result
    if _latest_evaluation_result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No evaluation run available. Please execute a run first via POST /api/evaluations/run.",
        )
    return _latest_evaluation_result


@app.get("/api/evaluations/export/json", tags=["Evaluation"])
async def export_evaluation_json():
    """Download the latest evaluation results as structured JSON."""
    global _latest_evaluation_result
    if _latest_evaluation_result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No evaluation run available to export. Run an evaluation first via POST /api/evaluations/run.",
        )
    json_data = export_suite_to_json(_latest_evaluation_result)
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={_latest_evaluation_result.run_id}.json"},
    )


@app.get("/api/evaluations/export/csv", tags=["Evaluation"])
async def export_evaluation_csv():
    """Download the latest evaluation results as tabular CSV."""
    global _latest_evaluation_result
    if _latest_evaluation_result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No evaluation run available to export. Run an evaluation first via POST /api/evaluations/run.",
        )
    csv_data = export_suite_to_csv(_latest_evaluation_result)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={_latest_evaluation_result.run_id}.csv"},
    )


@app.get("/", response_class=HTMLResponse, tags=["UI"])
async def serve_dashboard():
    """Render the main security analyst dashboard."""
    if not jinja_env:
        return HTMLResponse("<h1>Templates directory not found.</h1>", status_code=500)
    template = jinja_env.get_template("index.html")
    return HTMLResponse(template.render(app_name=settings.app_name, version="0.1.0"))
