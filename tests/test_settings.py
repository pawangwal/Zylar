import json
import logging

from zylar.core.logging import JsonFormatter
from zylar.core.settings import get_settings


def test_settings_use_safe_local_defaults(monkeypatch):
    monkeypatch.delenv("ZYLAR_ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("ZYLAR_OLLAMA_MODEL", raising=False)
    get_settings.cache_clear()

    settings = get_settings()

    assert str(settings.elasticsearch_url) == "http://127.0.0.1:9200/"
    assert settings.ollama_model == "mistral"
    assert settings.max_batch_size == 500


def test_json_logging_keeps_only_safe_context_identifiers():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="zylar.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="workflow complete",
        args=(),
        exc_info=None,
    )
    record.request_id = "request-123"
    record.incident_id = "incident-456"
    record.event_payload = {"password": "must-not-be-rendered"}

    payload = json.loads(formatter.format(record))

    assert payload["request_id"] == "request-123"
    assert payload["incident_id"] == "incident-456"
    assert "event_payload" not in payload
