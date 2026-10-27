"""Typed configuration loaded from environment variables and an optional .env file."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal, cast

from pydantic import AnyHttpUrl, Field, PositiveInt, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for Zylar.

    Environment variables are prefixed with ``ZYLAR_`` so unrelated process
    configuration cannot accidentally change security-sensitive values.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ZYLAR_",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    api_host: str = "127.0.0.1"
    api_port: PositiveInt = 8000
    request_timeout_seconds: PositiveInt = 10
    max_batch_size: PositiveInt = 500
    max_query_window_minutes: PositiveInt = 60

    elasticsearch_url: AnyHttpUrl = cast(AnyHttpUrl, "http://127.0.0.1:9200")
    elasticsearch_index: str = Field(default="zylar-logs", min_length=1, max_length=255)
    database_url: str = "postgresql+psycopg://zylar:change-me@127.0.0.1:5432/zylar"
    ollama_url: AnyHttpUrl = cast(AnyHttpUrl, "http://127.0.0.1:11434")
    ollama_model: str = Field(default="mistral", min_length=1, max_length=128)

    # This compatibility field disappears with the Slice 4 local-only adapter.
    legacy_classifier_model: str = Field(default="gpt-3.5-turbo", min_length=1, max_length=128)
    auth_signing_key: SecretStr = SecretStr("replace-with-a-long-random-secret")
    bootstrap_admin_username: str = Field(default="admin", min_length=1, max_length=64)
    bootstrap_admin_password: SecretStr = SecretStr("change-admin-password-in-production")
    token_expire_minutes: PositiveInt = 60


@lru_cache
def get_settings() -> Settings:
    """Return the immutable process-wide settings instance."""

    return Settings()
