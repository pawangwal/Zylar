# LLM Degradation & Deterministic Fallback Runbook

## 1. Architectural Role of LLM Inference

In Zylar, Large Language Model (LLM) inference—powered by a local Ollama runtime—is strictly an **optional semantic enrichment layer**.

### Deterministic Isolation Principles
1. **Core Detection is Deterministic**: Attack detection, rule matching, and initial event classification are computed strictly by deterministic rule algorithms in `src/zylar/analysis/detection_rules.py`.
2. **Risk Scoring is Mathematical**: Risk scores ($[0, 100]$) and severity categories are calculated via policy-weighted formulas in `src/zylar/analysis/risk_scoring.py`, completely independent of LLM availability.
3. **Correlation is Graph-Theoretic**: Entity graphs, hub centrality, and pivot nodes are computed via NetworkX in `src/zylar/analysis/correlation_service.py`.
4. **LLM Scope**: The LLM generates human-readable incident executive summaries and suggests remediation steps. If the LLM is degraded, unresponsive, or offline, Zylar automatically falls back to deterministic mitigation templates.

---

## 2. Circuit Breaker & Health Probe Contracts

### 2.1 Bounded Inference Timeout & Circuit Breaker
- In `src/zylar/core/settings.py`, `ollama_request_timeout_seconds` is bounded to a default of $5.0$ seconds.
- If Ollama fails to respond within $5.0$ seconds or throws a connection exception:
  - The inference call is aborted immediately.
  - A structured warning is logged.
  - The workflow produces a deterministic mitigation plan generated from the matched rule definitions and risk category.

### 2.2 Health Probe Behavior
- When Ollama is offline or degraded:
  - `GET /health/ready` returns HTTP 200 with JSON payload `{"status": "degraded", "checks": {"ollama": "degraded", "database": "healthy", "elasticsearch": "healthy"}}`.
  - The system remains fully operational for ingestion, incident triage, and dashboard monitoring.

---

## 3. Investigating & Restoring Ollama Service

### 3.1 Verify Local Ollama Connectivity

```bash
# Test Ollama API endpoint
curl -s http://127.0.0.1:11434/api/tags
```

### 3.2 Verify Required Model is Pulled

Zylar uses `mistral` (or `llama3.2`) for semantic enrichment:

```bash
# Check loaded models
ollama list

# If model is missing, pull target model
ollama pull mistral:latest
```

### 3.3 Restarting Ollama Service

```bash
# If running as system service
sudo systemctl restart ollama

# If running via Docker Compose (profile: llm)
docker compose --profile llm restart ollama
```

### 3.4 Validating Deterministic Fallback In Production

To verify that deterministic fallback works under simulated Ollama failure:

```bash
# 1. Point Zylar to non-existent Ollama endpoint
export ZYLAR_OLLAMA_HOST="http://127.0.0.1:19999"

# 2. Trigger workflow API
curl -X POST http://127.0.0.1:8000/api/workflow/run \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"events": [{"event_id": "test-1", "timestamp": "2026-10-31T00:00:00Z", "event_type": "auth_failure", "source_ip": "10.0.0.1", "user": "root"}]}'

# 3. Response succeeds with deterministic mitigation plan
```

