"""Configuration management for GuardRail using Pydantic Settings.

Design Decision:
We use Pydantic Settings to load and validate environment variables at startup.
This ensures fail-fast behavior: if a required configuration is invalid,
the application stops immediately rather than failing silently during a request.
Defaults are configured to allow offline, zero-cost execution out of the box.
"""

from pathlib import Path
from typing import Literal
from pydantic import AliasChoices, Field
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
    environment: Literal["development", "testing", "production"] = Field(
        default="development",
        validation_alias=AliasChoices("environment", "guardrail_env"),
    )
    debug: bool = Field(
        default=True,
        validation_alias=AliasChoices("debug", "guardrail_debug"),
    )

    # Database configuration
    database_path: str = Field(
        default=str(PROJECT_ROOT / "guardrail.db"),
        validation_alias=AliasChoices("database_path", "guardrail_database_path"),
    )

    # LLM Provider selection: 'mock' (offline) or 'gemini' (live API)
    provider: Literal["mock", "gemini"] = Field(
        default="mock",
        validation_alias=AliasChoices("provider", "guardrail_provider"),
    )
    gemini_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("gemini_api_key", "guardrail_gemini_api_key"),
    )

    # Resource constraints
    max_tool_iterations: int = Field(
        default=5,
        validation_alias=AliasChoices("max_tool_iterations", "guardrail_max_tool_iterations"),
    )
    default_document_limit: int = Field(
        default=5,
        validation_alias=AliasChoices("default_document_limit", "guardrail_default_document_limit"),
    )
    default_log_limit: int = Field(
        default=20,
        validation_alias=AliasChoices("default_log_limit", "guardrail_default_log_limit"),
    )


# Singleton instance accessible throughout the application
settings = Settings()
