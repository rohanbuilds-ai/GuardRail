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
from typing import List
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader

from guardrail.agent.investigator import AgentInvestigator
from guardrail.agent.orchestrator import AgentOrchestrator
from guardrail.config import PROJECT_ROOT, settings
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


@app.get("/", response_class=HTMLResponse, tags=["UI"])
async def serve_dashboard():
    """Render the main security analyst dashboard."""
    if not jinja_env:
        return HTMLResponse("<h1>Templates directory not found.</h1>", status_code=500)
    template = jinja_env.get_template("index.html")
    return HTMLResponse(template.render(app_name=settings.app_name, version="0.1.0"))
