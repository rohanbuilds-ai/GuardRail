# Multi-stage reproducible build for GuardRail
# Uses official Astral uv for deterministic, fast dependency resolution
FROM python:3.12-slim-bookworm AS base

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    PORT=8000 \
    HOST=0.0.0.0

# Install uv from official binary image
COPY --from=ghcr.io/astral-sh/uv:0.5.21 /uv /uvx /bin/

# Create non-root system user for secure container execution
RUN useradd -u 1000 -m -s /bin/bash appuser

WORKDIR /app

# Stage 1: Dependency caching layer
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Stage 2: Application source copy
COPY src/ /app/src/
COPY frontend/ /app/frontend/
COPY README.md /app/

# Install application project package into virtualenv
RUN uv sync --frozen --no-dev

# Ensure appropriate file ownership for non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Document exposed HTTP port
EXPOSE 8000

# Container healthcheck querying application /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# Start FastAPI server via uvicorn
CMD ["uvicorn", "guardrail.main:app", "--host", "0.0.0.0", "--port", "8000"]
