# Zylar

Zylar is a local, AI-assisted security operations centre (SOC) prototype. It
ingests security events, identifies suspicious activity, correlates evidence,
and produces advisory mitigation plans. It is being hardened through the
implementation plan before any production-readiness claim is made.

## Current status

The project is a prototype under active hardening. It does **not** execute
mitigation actions, provide automated remediation, or claim production
certification. The legacy classifier still exists temporarily while the next
implementation slice replaces every external AI path with a validated,
Ollama-only adapter.

## Development setup

Zylar supports Python 3.11 and 3.12. Use an isolated environment; do not
commit it.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

Set safe local service values in `.env`. Never commit that file.

## Quality commands

```powershell
ruff check src/zylar
mypy src/zylar
pytest
python -m pip wheel --no-deps --wheel-dir dist .
```

These commands run in CI on Python 3.11 and 3.12. Passing them establishes a
development baseline, not production readiness.

## Prototype services

The present prototype uses Elasticsearch for event search, SQLite for legacy
incident history, LangGraph for orchestration, and Streamlit for the analyst
dashboard. PostgreSQL will replace SQLite as the transactional system of record
in the planned persistence slice.

For local prototype experimentation only, start Elasticsearch/Kibana from
`elk_setup/`, then use separate shells for the simulator, API, and dashboard:

```powershell
python -m log_generator.simulate_attacks --duration 600
uvicorn api.main:app --host 127.0.0.1 --port 8000
streamlit run dashboard/app.py
```

The current Docker Compose file is development-only because Elasticsearch
security is disabled. Do not expose those services publicly.

## Architecture direction

Zylar remains a modular monolith:

- FastAPI is the API boundary.
- Elasticsearch stores and searches raw security events.
- PostgreSQL will own incidents, executions, audit data, and entity history.
- Ollama will provide local-only inference.
- Streamlit remains the initial analyst UI.
- Mitigation remains advisory only.

The phased implementation plan governs this work: repository hygiene and
reproducible tooling, canonical event contracts, API security, local inference,
PostgreSQL persistence, recoverable workflows, measured detection quality, and
secure deployment evidence.

## Repository rules

Do not commit virtual environments, bytecode, local databases, reports, model
artefacts, or `.env` files. Use `.env.example` as the configuration template.

## Project documentation

- [Phase 1 implementation report](docs/reports/phase-1-implementation-report.md)

## License

This project currently has no declared open-source license. Add one before any
public release.
