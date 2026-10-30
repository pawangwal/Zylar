"""Typed configuration loaded from environment variables and an optional .env file."""

from __future__ import annotations

import urllib.parse
from functools import lru_cache
from pathlib import Path
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
    elasticsearch_api_key: SecretStr | None = Field(
        default=None,
        description="API key for authenticating with Elasticsearch.",
    )
    elasticsearch_ca_certs: str | None = Field(
        default=None,
        description="Path to trusted CA certificate bundle for Elasticsearch TLS.",
    )
    elasticsearch_verify_certs: bool = Field(
        default=True,
        description="Whether to verify TLS certificates when connecting to HTTPS Elasticsearch.",
    )
    enable_ingestion_scheduler: bool = Field(
        default=True,
        description="Controls whether this process starts the autonomous background ingestion scheduler.",
    )
    database_url: str = "postgresql+psycopg://zylar:change-me@127.0.0.1:5434/zylar_db"
    db_pool_size: PositiveInt = 10
    db_max_overflow: int = Field(default=20, ge=0)
    db_pool_timeout_seconds: PositiveInt = 30
    db_pool_recycle_seconds: PositiveInt = 1800
    db_pool_pre_ping: bool = True

    api_db_pool_size: PositiveInt = Field(
        default=10,
        description="SQLAlchemy connection pool size for API process.",
    )
    api_db_max_overflow: int = Field(
        default=10,
        ge=0,
        description="SQLAlchemy connection max overflow for API process.",
    )
    worker_db_pool_size: PositiveInt = Field(
        default=5,
        description="SQLAlchemy connection pool size for Worker process.",
    )
    worker_db_max_overflow: int = Field(
        default=5,
        ge=0,
        description="SQLAlchemy connection max overflow for Worker process.",
    )
    max_workflow_concurrency: PositiveInt = Field(
        default=5,
        description="Process-local maximum concurrent LangGraph workflow runs in API process.",
    )

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
        """Returns the Elasticsearch URL with any password or API key masked for safe diagnostic logging."""
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
            if self.elasticsearch_api_key:
                host = parsed.hostname or ""
                port_str = f":{parsed.port}" if parsed.port else ""
                netloc = f"[api-key:***]@{host}{port_str}"
                return urllib.parse.urlunsplit(
                    (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
                )
            return str(self.elasticsearch_url)
        except Exception:
            return "[redacted-elasticsearch-url]"

    @property
    def elasticsearch_client_kwargs(self) -> dict[str, Any]:
        """Returns connection arguments for the elasticsearch.Elasticsearch client.

        Extracts a clean, credential-free host URL and supplies explicit basic_auth
        or api_key credentials from settings, enforcing TLS verification for HTTPS.
        """
        url_str = str(self.elasticsearch_url).rstrip("/")
        parsed = urllib.parse.urlsplit(url_str)
        host = parsed.hostname or "127.0.0.1"
        port_str = f":{parsed.port}" if parsed.port is not None else ""
        clean_url = f"{parsed.scheme}://{host}{port_str}{parsed.path}".rstrip("/")

        kwargs: dict[str, Any] = {
            "hosts": [clean_url],
            "request_timeout": self.request_timeout_seconds,
        }
        if parsed.scheme.lower() == "https":
            kwargs["verify_certs"] = self.elasticsearch_verify_certs
            if self.elasticsearch_ca_certs:
                kwargs["ca_certs"] = self.elasticsearch_ca_certs

        if self.elasticsearch_api_key:
            kwargs["api_key"] = self.elasticsearch_api_key.get_secret_value()
        elif self.elasticsearch_password:
            username = self.elasticsearch_username or parsed.username or "elastic"
            kwargs["basic_auth"] = (
                username,
                self.elasticsearch_password.get_secret_value(),
            )
        elif parsed.password:
            kwargs["basic_auth"] = (parsed.username or "elastic", parsed.password)

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

            # Single-instance database connection budget validation (1 API instance + 1 Worker instance + 5 reserved)
            total_budget = (
                self.api_db_pool_size
                + self.api_db_max_overflow
                + self.worker_db_pool_size
                + self.worker_db_max_overflow
                + 5
            )
            if total_budget > 50:
                raise ValueError(
                    f"In production, total database connection budget ({total_budget}) exceeds "
                    "safe single-instance capacity limit of 50 connections."
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
            except Exception as exc:
                raise ValueError("In production, ZYLAR_ELASTICSEARCH_URL is not a valid RFC-3986 URL.") from exc

            if parsed_es and parsed_es.password:
                raw_es_pwd = urllib.parse.unquote(parsed_es.password).strip()
                if raw_es_pwd in KNOWN_PLACEHOLDER_PASSWORDS or len(raw_es_pwd) < 8:
                    raise ValueError(
                        "In production, ZYLAR_ELASTICSEARCH_PASSWORD in URL must not use a known placeholder "
                        "and must be at least 8 characters long."
                    )

            if parsed_es and (parsed_es.username or parsed_es.password):
                raise ValueError(
                    "In production, ZYLAR_ELASTICSEARCH_URL must not embed credentials. "
                    "Configure credentials via ZYLAR_ELASTICSEARCH_USERNAME and ZYLAR_ELASTICSEARCH_PASSWORD "
                    "or ZYLAR_ELASTICSEARCH_API_KEY."
                )

            if parsed_es and parsed_es.scheme.lower() != "https":
                raise ValueError(
                    "In production, ZYLAR_ELASTICSEARCH_URL must use HTTPS (e.g., https://elasticsearch:9200)."
                )

            if not self.elasticsearch_verify_certs:
                raise ValueError(
                    "In production, ZYLAR_ELASTICSEARCH_VERIFY_CERTS must not be disabled."
                )

            if self.elasticsearch_ca_certs is not None:
                ca_path = Path(self.elasticsearch_ca_certs)
                if not ca_path.exists() or not ca_path.is_file():
                    raise ValueError(
                        f"In production, configured CA certificate bundle file does not exist: {self.elasticsearch_ca_certs}"
                    )

            if self.elasticsearch_api_key and self.elasticsearch_password:
                raise ValueError(
                    "In production, cannot configure both ZYLAR_ELASTICSEARCH_PASSWORD and "
                    "ZYLAR_ELASTICSEARCH_API_KEY. Choose one authentication method."
                )

            if not self.elasticsearch_api_key and not self.elasticsearch_password:
                raise ValueError(
                    "In production, Elasticsearch authentication is required. Provide either "
                    "ZYLAR_ELASTICSEARCH_PASSWORD (with ZYLAR_ELASTICSEARCH_USERNAME) or ZYLAR_ELASTICSEARCH_API_KEY."
                )

            if self.elasticsearch_password:
                if not self.elasticsearch_username or not self.elasticsearch_username.strip():
                    raise ValueError(
                        "In production, ZYLAR_ELASTICSEARCH_USERNAME must be explicitly specified "
                        "when using password authentication."
                    )

            if self.elasticsearch_api_key:
                api_key_val = self.elasticsearch_api_key.get_secret_value().strip()
                if len(api_key_val) < 8:
                    raise ValueError(
                        "In production, ZYLAR_ELASTICSEARCH_API_KEY must be at least 8 characters long."
                    )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the immutable process-wide settings instance."""

    return Settings()
