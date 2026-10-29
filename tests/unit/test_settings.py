from __future__ import annotations

import pytest
from pydantic import ValidationError

from zylar.core.settings import Settings

SYNTHETIC_KEY_32 = "synthetic-test-key-0123456789abcdef-32chars"
SYNTHETIC_ADMIN_PWD = "synthetic-admin-pass-12345"
SYNTHETIC_DB_URL = (
    "postgresql+psycopg://synthetic_app:synthetic_db_pass_123@synthetic.internal:5432/zylar_test"
)


def test_default_settings_in_development(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ZYLAR_ENVIRONMENT", raising=False)
    settings = Settings()
    assert settings.environment == "development"
    assert settings.elasticsearch_index == "zylar-logs"
    assert settings.max_batch_size == 500


def test_environment_override_from_env_var(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ZYLAR_ENVIRONMENT", "test")
    settings = Settings()
    assert settings.environment == "test"


def test_production_rejects_default_signing_key():
    with pytest.raises(ValidationError, match="ZYLAR_AUTH_SIGNING_KEY"):
        Settings(
            _env_file=None,
            auth_signing_key="replace-with-a-long-random-secret",
            environment="production",
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
        )


def test_production_rejects_short_signing_key():
    with pytest.raises(ValidationError, match="ZYLAR_AUTH_SIGNING_KEY"):
        Settings(
            environment="production",
            auth_signing_key="too-short-key",
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
        )


def test_production_rejects_default_admin_password():
    with pytest.raises(ValidationError, match="ZYLAR_BOOTSTRAP_ADMIN_PASSWORD"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            database_url=SYNTHETIC_DB_URL,
            bootstrap_admin_password="change-admin-password-in-production",
        )


def test_production_rejects_placeholder_database_url():
    with pytest.raises(ValidationError, match="ZYLAR_DATABASE_URL"):
        Settings(
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url="postgresql+psycopg://zylar:change-me@127.0.0.1:5432/zylar",
        )


def test_production_rejects_empty_database_password():
    with pytest.raises(ValidationError, match="non-empty database password"):
        Settings(
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url="postgresql+psycopg://synthetic_user@synthetic.internal:5432/zylar",
        )


def test_production_rejects_short_database_password():
    with pytest.raises(ValidationError, match="at least 8 characters"):
        Settings(
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url="postgresql+psycopg://synthetic_user:short@synthetic.internal:5432/zylar",
        )


def test_production_rejects_non_postgresql_scheme():
    with pytest.raises(ValidationError, match="PostgreSQL scheme"):
        Settings(
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url="mysql://synthetic_user:synthetic_pass_123@synthetic.internal:3306/zylar",
        )


def test_production_rejects_url_encoded_placeholder_password():
    # 'change%2Dme' unquotes to 'change-me'
    with pytest.raises(ValidationError, match="known placeholder"):
        Settings(
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url="postgresql+psycopg://synthetic_user:change%2Dme@synthetic.internal:5432/zylar",
        )


def test_production_accepts_valid_secrets_with_url_encoding():
    settings = Settings(
        environment="production",
        auth_signing_key=SYNTHETIC_KEY_32,
        bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
        database_url="postgresql+psycopg://synthetic_app:synth%23pass%2199@synthetic.internal:5432/zylar_test",
    )
    assert settings.environment == "production"
    assert settings.auth_signing_key.get_secret_value() == SYNTHETIC_KEY_32


def test_redacted_database_url_masks_password():
    settings = Settings(
        database_url="postgresql+psycopg://app_user:secret_password_here@db.example.internal:5432/soc_db"
    )
    redacted = settings.redacted_database_url
    assert "secret_password_here" not in redacted
    assert "app_user:***@db.example.internal:5432/soc_db" in redacted


def test_default_elasticsearch_auth_settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ZYLAR_ELASTICSEARCH_USERNAME", raising=False)
    monkeypatch.delenv("ZYLAR_ELASTICSEARCH_PASSWORD", raising=False)
    monkeypatch.delenv("ZYLAR_ELASTICSEARCH_URL", raising=False)
    settings = Settings(_env_file=None)
    assert settings.elasticsearch_username == "elastic"
    assert settings.elasticsearch_password is None
    assert str(settings.elasticsearch_url) == "http://127.0.0.1:9200/"
    assert settings.redacted_elasticsearch_url == "http://127.0.0.1:9200/"


def test_redacted_elasticsearch_url_masks_password():
    settings = Settings(
        _env_file=None,
        elasticsearch_url="http://elastic:supersecret@127.0.0.1:9200",
    )
    redacted = settings.redacted_elasticsearch_url
    assert "supersecret" not in redacted
    assert "elastic:***@127.0.0.1:9200" in redacted


def test_redacted_elasticsearch_url_masks_password_from_secret():
    settings = Settings(
        _env_file=None,
        elasticsearch_url="http://127.0.0.1:9200",
        elasticsearch_username="elastic",
        elasticsearch_password="my_es_password",
    )
    redacted = settings.redacted_elasticsearch_url
    assert "my_es_password" not in redacted
    assert "elastic:***@127.0.0.1:9200" in redacted


def test_production_rejects_placeholder_elasticsearch_password():
    with pytest.raises(ValidationError, match="ZYLAR_ELASTICSEARCH_PASSWORD"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_password="change-me",
        )


def test_production_rejects_placeholder_in_elasticsearch_url():
    with pytest.raises(ValidationError, match="ZYLAR_ELASTICSEARCH_PASSWORD in URL"):
        Settings(
            _env_file=None,
            environment="production",
            auth_signing_key=SYNTHETIC_KEY_32,
            bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
            database_url=SYNTHETIC_DB_URL,
            elasticsearch_url="http://elastic:password@127.0.0.1:9200",
        )


def test_production_accepts_valid_elasticsearch_password():
    settings = Settings(
        _env_file=None,
        environment="production",
        auth_signing_key=SYNTHETIC_KEY_32,
        bootstrap_admin_password=SYNTHETIC_ADMIN_PWD,
        database_url=SYNTHETIC_DB_URL,
        elasticsearch_password="a-very-strong-production-pass",
    )
    assert settings.elasticsearch_password.get_secret_value() == "a-very-strong-production-pass"


def test_elasticsearch_client_kwargs_default_and_custom(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ZYLAR_ELASTICSEARCH_USERNAME", raising=False)
    monkeypatch.delenv("ZYLAR_ELASTICSEARCH_PASSWORD", raising=False)
    monkeypatch.delenv("ZYLAR_ELASTICSEARCH_URL", raising=False)
    s1 = Settings(_env_file=None, elasticsearch_url="http://127.0.0.1:9200")
    assert s1.elasticsearch_client_kwargs == {
        "hosts": ["http://127.0.0.1:9200"],
        "request_timeout": 10,
    }

    s2 = Settings(
        _env_file=None,
        elasticsearch_url="http://127.0.0.1:9200",
        elasticsearch_username="custom_user",
        elasticsearch_password="custom_password",
    )
    assert s2.elasticsearch_client_kwargs == {
        "hosts": ["http://127.0.0.1:9200"],
        "request_timeout": 10,
        "basic_auth": ("custom_user", "custom_password"),
    }



