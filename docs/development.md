# Local Development, Testing & Verification Guide

This guide details the local setup, testing workflow, linting commands, and container verification procedures for the GuardRail project.

---

## 1. Prerequisites

- **Python**: Version `3.11`, `3.12`, or `3.13`.
- **Package Manager**: [uv](https://docs.astral.sh/uv/) (`>=0.5.0`).
- **Operating System**: Windows, Linux, or macOS.
- **Docker** *(Optional)*: Required only if testing container images locally.

---

## 2. Setup & Virtual Environment

GuardRail uses `uv` for reproducible, lightning-fast dependency management locked to `uv.lock`.

```powershell
# 1. Clone the repository locally
git clone <local-path> GuardRail
cd GuardRail

# 2. Sync all project dependencies and development tools
uv sync --all-extras

# 3. Create a local environment file from template
cp .env.example .env
```

The application defaults to `PROVIDER=mock`, requiring zero API keys, cloud billing, or network access.

---

## 3. Running the Local Application

Start the FastAPI application and background MCP subsystem:

```powershell
uv run uvicorn guardrail.main:app --host 127.0.0.1 --port 8000 --reload
```

Once running:
- **Analyst Dashboard**: Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in your browser.
- **Interactive OpenAPI Docs**: Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
- **Health & Telemetry**: Query [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health).

---

## 4. Running the Test Suite

The test suite consists of 74 unit and integration tests covering the database, MCP server, agents, security policies, canaries, sanitizers, and evaluation engine.

```powershell
# Run the complete test suite with verbose output
uv run pytest -v

# Run only unit tests
uv run pytest tests/unit/ -v

# Run only integration tests
uv run pytest tests/integration/ -v

# Run a specific test file
uv run pytest tests/integration/test_baseline_vs_hardened.py -v
```

---

## 5. Quality Assurance & Static Checks

Run the same static verification checks executed by our GitHub Actions CI pipeline:

```powershell
# 1. Static Python syntax compilation across all packages
uv run python -m compileall src tests

# 2. Linting verification for fatal flaws and syntax invariants
uvx ruff check --select E9,F63,F7,F82 src tests

# 3. Check Git formatting and whitespace
git diff --check
```

---

## 6. Docker Containerization (Optional)

If Docker Desktop is installed and running on your system, you can verify container execution:

```powershell
# 1. Build the local image
docker build -t guardrail:latest .

# 2. Start the container in detached mode
docker run -d --name guardrail-app -p 8000:8000 guardrail:latest

# 3. Verify container health
curl -s http://127.0.0.1:8000/health

# 4. View logs
docker logs guardrail-app

# 5. Stop and clean up container
docker stop guardrail-app
docker rm guardrail-app
```

Or using Docker Compose:
```powershell
docker compose up -d
docker compose logs -f
docker compose down
```

> [!NOTE]
> If Docker is not installed on your machine, normal application operation and tests are completely unaffected since GuardRail runs directly via `uv`.

---

## 7. Git & Version Control Guidelines

- Work incrementally on `main` or feature branches.
- Verify all tests pass before making commits.
- Never commit `.env` files, virtual environments, local database files (`*.db`), or runtime logs.
