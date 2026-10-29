"""Typed configuration loaded from environment variables and an optional .env file."""

from __future__ import annotations

import urllib.parse
from functools import lru_cache
from typing import Any, Literal, cast

from pydantic import AnyHttpUrl, Field, PositiveInt, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

KNOWN_PLACEHOLDER_KEYS: frozenset[str] = frozenset(
    {
        "replace-with-a-long-random-secret",
        "secret",
        "changeme",
        "default",
        "jwt-secret",
        "replace-me",
    }
)

KNOWN_PLACEHOLDER_PASSWORDS: frozenset[str] = frozenset(
    {
        "change-admin-password-in-production",
        "change-me",
        "changeme",
        "password",
        "admin",
        "root",
        "secret",
        "replace-me",
        "123456",
        "test",
    }
)


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
    elasticsearch_username: str = Field(default="elastic", min_length=1, max_length=128)
    elasticsearch_password: SecretStr | None = None
    database_url: str = "postgresql+psycopg://zylar:change-me@127.0.0.1:5434/zylar_db"
    db_pool_size: PositiveInt = 10
    db_max_overflow: int = Field(default=20, ge=0)
    db_pool_timeout_seconds: PositiveInt = 30
    db_pool_recycle_seconds: PositiveInt = 1800
    db_pool_pre_ping: bool = True
    ollama_url: AnyHttpUrl = cast(AnyHttpUrl, "http://127.0.0.1:11434")
    ollama_model: str = Field(default="mistral", min_length=1, max_length=128)
    auth_signing_key: SecretStr = SecretStr("replace-with-a-long-random-secret")
    bootstrap_admin_username: str = Field(default="admin", min_length=1, max_length=64)
    bootstrap_admin_password: SecretStr = SecretStr("change-admin-password-in-production")
    token_expire_minutes: PositiveInt = 60
    trusted_proxies: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "::1"],
        description="Trusted reverse proxy IP addresses allowed to provide forwarded headers",
    )

    @property
    def redacted_database_url(self) -> str:
        """Returns the database URL with the password masked for safe diagnostic logging."""
        try:
            parsed = urllib.parse.urlsplit(self.database_url)
            if parsed.password:
                user = parsed.username or ""
                host = parsed.hostname or ""
                port_str = f":{parsed.port}" if parsed.port else ""
                netloc = f"{user}:***@{host}{port_str}"
                return urllib.parse.urlunsplit(
                    (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
                )
            return self.database_url
        except Exception:
            return "[redacted-database-url]"

    @property
    def redacted_elasticsearch_url(self) -> str:
        """Returns the Elasticsearch URL with any password masked for safe diagnostic logging."""
        try:
            parsed = urllib.parse.urlsplit(str(self.elasticsearch_url))
            if parsed.password:
                user = parsed.username or ""
                host = parsed.hostname or ""
                port_str = f":{parsed.port}" if parsed.port else ""
                netloc = f"{user}:***@{host}{port_str}"
                return urllib.parse.urlunsplit(
                    (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
                )
            if self.elasticsearch_password:
                user = self.elasticsearch_username or "elastic"
                host = parsed.hostname or ""
                port_str = f":{parsed.port}" if parsed.port else ""
                netloc = f"{user}:***@{host}{port_str}"
                return urllib.parse.urlunsplit(
                    (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
                )
            return str(self.elasticsearch_url)
        except Exception:
            return "[redacted-elasticsearch-url]"

    @property
    def elasticsearch_client_kwargs(self) -> dict[str, Any]:
        """Returns connection arguments for the elasticsearch.Elasticsearch client."""
        url_str = str(self.elasticsearch_url).rstrip("/")
        parsed = urllib.parse.urlsplit(url_str)
        kwargs: dict[str, Any] = {
            "hosts": [url_str],
            "request_timeout": self.request_timeout_seconds,
        }
        if not parsed.password and self.elasticsearch_password:
            kwargs["basic_auth"] = (
                self.elasticsearch_username,
                self.elasticsearch_password.get_secret_value(),
            )
        return kwargs

    @model_validator(mode="after")
    def validate_production_secrets(self) -> Settings:
        """Enforces that production deployments do not use placeholder or weak secrets."""
        if self.environment == "production":
            key_val = self.auth_signing_key.get_secret_value().strip()
            if key_val in KNOWN_PLACEHOLDER_KEYS or len(key_val) < 32:
                raise ValueError(
                    "In production, ZYLAR_AUTH_SIGNING_KEY must be a cryptographically strong "
                    "secret at least 32 characters long."
                )
            pwd_val = self.bootstrap_admin_password.get_secret_value().strip()
            if pwd_val in KNOWN_PLACEHOLDER_PASSWORDS or len(pwd_val) < 12:
                raise ValueError(
                    "In production, ZYLAR_BOOTSTRAP_ADMIN_PASSWORD must be changed from the "
                    "default placeholder and be at least 12 characters long."
                )

            try:
                parsed = urllib.parse.urlsplit(self.database_url)
            except Exception as exc:
                raise ValueError(
                    "In production, ZYLAR_DATABASE_URL is not a valid RFC-3986 URL."
                ) from exc

            scheme = parsed.scheme.lower()
            if not (scheme == "postgresql" or scheme.startswith("postgresql+")):
                raise ValueError(
                    "In production, ZYLAR_DATABASE_URL must use a PostgreSQL scheme (e.g., postgresql+psycopg://)."
                )

            if not parsed.hostname:
                raise ValueError("In production, ZYLAR_DATABASE_URL must specify a database host.")

            if not parsed.username or parsed.username.strip() in KNOWN_PLACEHOLDER_PASSWORDS:
                raise ValueError(
                    "In production, ZYLAR_DATABASE_URL must specify a non-empty, non-placeholder username."
                )

            if not parsed.password:
                raise ValueError(
                    "In production, ZYLAR_DATABASE_URL must specify a non-empty database password."
                )

            raw_db_password = urllib.parse.unquote(parsed.password).strip()
            if raw_db_password in KNOWN_PLACEHOLDER_PASSWORDS:
                raise ValueError(
                    "In production, ZYLAR_DATABASE_URL password must not use a known placeholder value."
                )
            if len(raw_db_password) < 8:
                raise ValueError(
                    "In production, ZYLAR_DATABASE_URL password must be at least 8 characters long."
                )

            if self.elasticsearch_password:
                es_pwd = self.elasticsearch_password.get_secret_value().strip()
                if es_pwd in KNOWN_PLACEHOLDER_PASSWORDS or len(es_pwd) < 8:
                    raise ValueError(
                        "In production, ZYLAR_ELASTICSEARCH_PASSWORD must not use a known placeholder "
                        "and must be at least 8 characters long."
                    )

            try:
                parsed_es = urllib.parse.urlsplit(str(self.elasticsearch_url))
            except Exception:
                parsed_es = None

            if parsed_es and parsed_es.password:
                raw_es_pwd = urllib.parse.unquote(parsed_es.password).strip()
                if raw_es_pwd in KNOWN_PLACEHOLDER_PASSWORDS or len(raw_es_pwd) < 8:
                    raise ValueError(
                        "In production, ZYLAR_ELASTICSEARCH_PASSWORD in URL must not use a known placeholder "
                        "and must be at least 8 characters long."
                    )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the immutable process-wide settings instance."""

    return Settings()
