# ADR-002: Optional Local LLM Inference with Circuit-Breaker Fallback

## Context and Problem Statement

Generative AI and Large Language Models (LLMs) can assist human SOC analysts by generating incident executive summaries and suggesting context-aware mitigation actions. However, treating LLMs as a hard operational dependency in a mission-critical cybersecurity system introduces catastrophic reliability and security vulnerabilities:
1. **Service Fragility**: LLM inference runtimes (local Ollama or remote cloud APIs) suffer high latency ($1\text{–}10\text{ seconds}$), memory pressure, GPU OOM crashes, or network timeouts.
2. **Hallucination Risk**: LLMs cannot be trusted to perform deterministic mathematical calculations, calculate risk scores, or classify attack rules reliably.
3. **Privacy and Data Exfiltration**: Sending raw internal security logs to external cloud AI APIs introduces severe compliance and data governance risks.

## Decision Drivers

- Core SOC detection, classification, and scoring must be 100% deterministic, testable, and mathematically verified.
- The platform must function with complete integrity even when the LLM service is completely offline or unresponsive.
- Air-gapped / local inference requirement: All intelligence processing must run locally without external network dependencies.
- Strict latency bounding: Workflow execution must never hang waiting on an LLM response.

## Considered Options

1. **Mandatory Cloud LLM (OpenAI / Anthropic)**: Route all incident reasoning to external frontier model APIs.
2. **Mandatory Local LLM (Ollama)**: Require local Ollama to be healthy before processing any incident batch.
3. **Optional Local LLM with Deterministic Circuit Breaker (Chosen)**: Local Ollama runtime used exclusively for narrative enrichment, bounded by a strict 5-second timeout and automatic fallback to rule-based mitigation templates.

## Decision Outcome

Chosen option: **Optional Local LLM with Deterministic Circuit Breaker (Option 3)**.

### Architectural Rules:
1. **Deterministic Rule Engine**: Rules (`RULE_BRUTE_FORCE_AUTH`, `RULE_PORT_SCAN_REJECT`, `RULE_RANSOMWARE_INDICATOR`, `RULE_RANSOMWARE_MASS_ENCRYPTION`) evaluate exclusively via Python code in `src/zylar/analysis/detection_rules.py`.
2. **Mathematical Risk Policy**: Risk scores ($[0, 100]$) and categories evaluate via validated weight normalization formulas in `src/zylar/analysis/risk_scoring.py`.
3. **Circuit-Breaker Bounding**: Ollama client requests enforce a maximum timeout of $5.0$ seconds (`ollama_request_timeout_seconds`). On timeout or failure, the agent immediately emits the pre-calculated deterministic mitigation plan.
4. **Health Reporting**: When Ollama is offline, `/health/ready` returns HTTP 200 with `status: "degraded"` and `checks: {"ollama": "degraded"}`, ensuring core operations continue unhindered.

### Consequences

#### Positive:
- Uncompromised reliability: Ingestion and incident triage continue at full speed even during local LLM restart or model pulling.
- Zero external data leakage: No security event data ever leaves the local enterprise boundary.
- Verifiability: Unit tests verify all detection rules and risk scoring without mocking external LLM endpoints.

#### Negative:
- Local hardware requirement: Running local 7B models requires $\ge 8\text{ GB}$ of host RAM.

