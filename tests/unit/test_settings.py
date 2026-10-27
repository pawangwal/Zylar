from __future__ import annotations

import pytest
from pydantic import ValidationError

from zylar.core.settings import Settings


def test_default_settings_in_development():
    settings = Settings()
    assert settings.environment == "development"
    assert settings.elasticsearch_index == "zylar-logs"
    assert settings.max_batch_size == 500


def test_production_rejects_default_signing_key():
    with pytest.raises(ValidationError, match="ZYLAR_AUTH_SIGNING_KEY"):
        Settings(
            environment="production",
            bootstrap_admin_password="very-strong-admin-password-1234",
            database_url="postgresql+psycopg://app:real-secret@db.internal:5432/zylar",
        )


def test_production_rejects_short_signing_key():
    with pytest.raises(ValidationError, match="ZYLAR_AUTH_SIGNING_KEY"):
        Settings(
            environment="production",
            auth_signing_key="too-short",
            bootstrap_admin_password="very-strong-admin-password-1234",
            database_url="postgresql+psycopg://app:real-secret@db.internal:5432/zylar",
        )


def test_production_rejects_default_admin_password():
    with pytest.raises(ValidationError, match="ZYLAR_BOOTSTRAP_ADMIN_PASSWORD"):
        Settings(
            environment="production",
            auth_signing_key="a-very-long-production-cryptographic-secret-key-32chars",
            database_url="postgresql+psycopg://app:real-secret@db.internal:5432/zylar",
        )


def test_production_rejects_placeholder_database_url():
    with pytest.raises(ValidationError, match="ZYLAR_DATABASE_URL"):
        Settings(
            environment="production",
            auth_signing_key="a-very-long-production-cryptographic-secret-key-32chars",
            bootstrap_admin_password="very-strong-admin-password-1234",
            database_url="postgresql+psycopg://zylar:change-me@127.0.0.1:5432/zylar",
        )


def test_production_accepts_valid_secrets():
    settings = Settings(
        environment="production",
        auth_signing_key="a-very-long-production-cryptographic-secret-key-32chars",
        bootstrap_admin_password="very-strong-admin-password-1234",
        database_url="postgresql+psycopg://app:real-secret@db.internal:5432/zylar",
    )
    assert settings.environment == "production"
    assert settings.auth_signing_key.get_secret_value() == "a-very-long-production-cryptographic-secret-key-32chars"
