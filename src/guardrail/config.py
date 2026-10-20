"""Configuration management for GuardRail using Pydantic Settings.

Design Decision:
We use Pydantic Settings to load and validate environment variables at startup.
This ensures fail-fast behavior: if a required configuration is invalid,
the application stops immediately rather than failing silently during a request.
Defaults are configured to allow offline, zero-cost execution out of the box.
"""

from pathlib import Path
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "GuardRail Secure AI Lab"
    environment: Literal["development", "testing", "production"] = "development"
    debug: bool = True

    # Database configuration
    database_path: str = str(PROJECT_ROOT / "guardrail.db")

    # LLM Provider selection: 'mock' (offline) or 'gemini' (live API)
    provider: Literal["mock", "gemini"] = "mock"
    gemini_api_key: str = ""

    # Resource constraints
    max_tool_iterations: int = 5
    default_document_limit: int = 5
    default_log_limit: int = 20


# Singleton instance accessible throughout the application
settings = Settings()
