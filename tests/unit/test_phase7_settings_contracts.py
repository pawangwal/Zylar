from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from zylar.core.settings import Settings

SYNTHETIC_KEY_32 = "synthetic-test-key-0123456789abcdef-32chars"
SYNTHETIC_ADMIN_PWD = "synthetic-admin-pass-12345"
SYNTHETIC_DB_URL = (
    "postgresql+psycopg://synthetic_app:synthetic_db_pass_123@synthetic.internal:5432/zylar_test"
)
SYNTHETIC_ES_URL = "https://synthetic-es.internal:9200"


def test_production_accepts_valid_api_key():
    """Production mode must accept HTTPS Elasticsearch with API key authentication."""
    s = Settings(
        _env_file=None,
        environment="production",
        auth_signing_key=SYNTHETIC_KEY_32,
        bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
        database_url=SYNTHETIC_DB_URL,
        elasticsearch_url=SYNTHETIC_ES_URL,
        elasticsearch_api_key=SecretStr("valid-production-api-key-1234"),
    )
    assert s.elasticsearch_api_key is not None
    assert s.elasticsearch_api_key.get_secret_value() == "valid-production-api-key-1234"
    kwargs = s.elasticsearch_client_kwargs
    assert kwargs.get("api_key") == "valid-production-api-key-1234"
    assert "basic_auth" not in kwargs
    assert kwargs.get("verify_certs") is True


def test_production_accepts_valid_basic_auth():
    """Production mode must accept HTTPS Elasticsearch with explicit username and password."""
    s = Settings(
        _env_file=None,
        environment="production",
        auth_signing_key=SYNTHETIC_KEY_32,
        bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
        database_url=SYNTHETIC_DB_URL,
        elasticsearch_url=SYNTHETIC_ES_URL,
        elasticsearch_username="secops_worker",
        elasticsearch_password=SecretStr("valid-production-es-password-1234"),
    )
    assert s.elasticsearch_password is not None
    assert s.elasticsearch_password.get_secret_value() == "valid-production-es-password-1234"
    kwargs = s.elasticsearch_client_kwargs
    assert kwargs.get("basic_auth") == ("secops_worker", "valid-production-es-password-1234")
    assert "api_key" not in kwargs
    assert kwargs.get("verify_certs") is True


def test_production_rejects_missing_elasticsearch_credentials():
    """Production mode must fail closed if no credentials (password or API key) are provided."""
    with pytest.raises(ValidationError, match="Elasticsearch authentication is required"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_url=SYNTHETIC_ES_URL,
            elasticsearch_password=None,
            elasticsearch_api_key=None,
        )


def test_production_rejects_http_scheme():
    """Production mode must reject insecure HTTP Elasticsearch URLs."""
    with pytest.raises(ValidationError, match="ZYLAR_ELASTICSEARCH_URL must use HTTPS"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_url="http://synthetic-es.internal:9200",
            elasticsearch_api_key=SecretStr("valid-production-api-key-1234"),
        )


def test_production_rejects_empty_username_with_password():
    """Production mode must reject password authentication when username is empty or whitespace."""
    with pytest.raises(ValidationError, match="ZYLAR_ELASTICSEARCH_USERNAME must be explicitly specified"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_url=SYNTHETIC_ES_URL,
            elasticsearch_username="   ",
            elasticsearch_password=SecretStr("valid-production-es-password-1234"),
        )


def test_production_rejects_conflicting_authentication_methods():
    """Production mode must reject configuring both basic authentication and API key."""
    with pytest.raises(ValidationError, match="cannot configure both"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_url=SYNTHETIC_ES_URL,
            elasticsearch_username="secops_worker",
            elasticsearch_password=SecretStr("valid-production-es-password-1234"),
            elasticsearch_api_key=SecretStr("valid-production-api-key-1234"),
        )


def test_production_rejects_embedded_url_credentials():
    """Production mode must reject credentials embedded directly in the connection URL."""
    with pytest.raises(ValidationError, match="must not embed credentials"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_url="https://secops_user:super_secret_pwd@synthetic-es.internal:9200",
            elasticsearch_password=SecretStr("valid-production-es-password-1234"),
        )


def test_production_rejects_disabled_tls_verification():
    """Production mode must reject disabling TLS certificate verification."""
    with pytest.raises(ValidationError, match="ZYLAR_ELASTICSEARCH_VERIFY_CERTS must not be disabled"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_url=SYNTHETIC_ES_URL,
            elasticsearch_verify_certs=False,
            elasticsearch_api_key=SecretStr("valid-production-api-key-1234"),
        )


def test_production_rejects_invalid_ca_cert_path(tmp_path: Path):
    """Production mode must fail closed if a configured CA certificate bundle file does not exist."""
    nonexistent = tmp_path / "missing_ca.crt"
    with pytest.raises(ValidationError, match="CA certificate bundle file does not exist"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_url=SYNTHETIC_ES_URL,
            elasticsearch_ca_certs=str(nonexistent),
            elasticsearch_api_key=SecretStr("valid-production-api-key-1234"),
        )


def test_production_accepts_valid_custom_ca_cert(tmp_path: Path):
    """Production mode must accept a valid existing CA bundle and propagate it to client kwargs."""
    ca_file = tmp_path / "valid_ca.crt"
    ca_file.write_text("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
    s = Settings(
        _env_file=None,
        environment="production",
        auth_signing_key=SYNTHETIC_KEY_32,
        bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
        database_url=SYNTHETIC_DB_URL,
        elasticsearch_url=SYNTHETIC_ES_URL,
        elasticsearch_ca_certs=str(ca_file),
        elasticsearch_api_key=SecretStr("valid-production-api-key-1234"),
    )
    kwargs = s.elasticsearch_client_kwargs
    assert kwargs.get("ca_certs") == str(ca_file)
    assert kwargs.get("verify_certs") is True


def test_production_accepts_system_ca_trust():
    """Custom CA is optional; HTTPS with default system CA trust must verify certificates."""
    s = Settings(
        _env_file=None,
        environment="production",
        auth_signing_key=SYNTHETIC_KEY_32,
        bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
        database_url=SYNTHETIC_DB_URL,
        elasticsearch_url=SYNTHETIC_ES_URL,
        elasticsearch_ca_certs=None,
        elasticsearch_api_key=SecretStr("valid-production-api-key-1234"),
    )
    kwargs = s.elasticsearch_client_kwargs
    assert kwargs.get("verify_certs") is True
    assert "ca_certs" not in kwargs


def test_single_instance_connection_budget_validation():
    """Total connection budget formula must reject configurations exceeding safe headroom (50)."""
    with pytest.raises(ValidationError, match="total database connection budget .* exceeds safe single-instance capacity limit"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_url=SYNTHETIC_ES_URL,
            elasticsearch_api_key=SecretStr("valid-production-api-key-1234"),
            api_db_pool_size=25,
            api_db_max_overflow=15,
            worker_db_pool_size=15,
            worker_db_max_overflow=10,
        )


def test_default_pool_settings_and_workflow_concurrency():
    """Default pool settings and workflow concurrency must have explicit, documented bounds."""
    s = Settings(_env_file=None)
    assert s.api_db_pool_size == 10
    assert s.api_db_max_overflow == 10
    assert s.worker_db_pool_size == 5
    assert s.worker_db_max_overflow == 5
    assert s.max_workflow_concurrency == 5

    # Single-instance total budget: 1 * (10 + 10) + 1 * (5 + 5) + 5 = 35 <= 50
    total_budget = (
        s.api_db_pool_size
        + s.api_db_max_overflow
        + s.worker_db_pool_size
        + s.worker_db_max_overflow
        + 5
    )
    assert total_budget == 35
    assert total_budget <= 50


def test_development_backward_compatibility():
    """Development environment must permit HTTP without credentials and with default pool settings."""
    s = Settings(_env_file=None, environment="development")
    assert s.environment == "development"
    assert str(s.elasticsearch_url) == "http://127.0.0.1:9200/"
    assert s.elasticsearch_password is None
    assert s.elasticsearch_api_key is None
    kwargs = s.elasticsearch_client_kwargs
    assert kwargs["hosts"] == ["http://127.0.0.1:9200"]
    assert "basic_auth" not in kwargs
    assert "api_key" not in kwargs


def test_secrets_never_leak_in_redacted_urls_or_errors():
    """Passphrase and API key secrets must be masked in redacted URLs."""
    s = Settings(
        _env_file=None,
        elasticsearch_url="https://127.0.0.1:9200",
        elasticsearch_api_key=SecretStr("secret-top-token-9999"),
    )
    redacted = s.redacted_elasticsearch_url
    assert "secret-top-token-9999" not in redacted
    assert "***" in redacted


def test_elasticsearch_client_initialization_compatibility():
    """Elasticsearch client kwargs can be consumed by elasticsearch.Elasticsearch constructor."""
    s = Settings(
        _env_file=None,
        elasticsearch_url="https://es.example.internal:9200",
        elasticsearch_api_key=SecretStr("valid-api-key-1234"),
    )
    kwargs = s.elasticsearch_client_kwargs
    with patch("elasticsearch.Elasticsearch") as mock_es:
        mock_es(**kwargs)
        mock_es.assert_called_once_with(
            hosts=["https://es.example.internal:9200"],
            request_timeout=10,
            verify_certs=True,
            api_key="valid-api-key-1234",
        )
