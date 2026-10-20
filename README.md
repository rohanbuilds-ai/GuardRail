# GuardRail: Secure AI Agent & MCP Red-Team Lab

A portfolio-quality engineering lab evaluating AI agent security, Model Context Protocol (MCP) tool integration, and deterministic red-team evaluation against controlled threats.

## Phase 1: Minimal Vertical Slice

Currently in Phase 1:
- FastAPI backend with SQLite storage and seeded synthetic security incidents (`INC-001`, `INC-002`).
- Read-only document search tool (`search_incident_documents`).
- Deterministic mock LLM provider for zero-cost, reproducible agent runs.
- Interactive security analyst dashboard.
- Full unit and integration test coverage.
