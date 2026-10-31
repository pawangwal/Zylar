# Incident Investigation & Response Runbook

## 1. Overview & Triage Matrix

This runbook guides SOC analysts and incident responders in triaging, investigating, and mitigating security incidents detected and managed by the Zylar autonomous SOC platform.

### Incident Severity & SLA Matrix

| Severity | Risk Score | SLA to Acknowledge | SLA to Mitigate | Escalation Trigger |
| :--- | :--- | :--- | :--- | :--- |
| **P1 - Critical** | 80 – 100 | $\le 15\text{ minutes}$ | $\le 2\text{ hours}$ | Mass ransomware encryption, active lateral movement, domain controller compromise. |
| **P2 - High** | 60 – 79 | $\le 30\text{ minutes}$ | $\le 4\text{ hours}$ | High-volume brute-force attacks, port sweep with multiple open services compromised. |
| **P3 - Medium** | 30 – 59 | $\le 2\text{ hours}$ | $\le 8\text{ hours}$ | Suspicious anomalous port probe, localized single-user authentication anomalies. |
| **P4 - Low** | 0 – 29 | $\le 8\text{ hours}$ | $\le 24\text{ hours}$ | Informational audit events, benign network scans without service interaction. |

---

## 2. Investigation Workflow

### Step 1: Identify Incident Context in PostgreSQL

Connect to the authoritative PostgreSQL database as `zylar_read` (or `zylar_app`):

```bash
psql "postgresql://zylar_read:${ZYLAR_READ_DB_PASSWORD}@127.0.0.1:5432/zylar_db"
```

Query the latest active incidents:

```sql
SELECT 
    incident_id, 
    attack_classification, 
    risk_score, 
    risk_category, 
    timestamp, 
    idempotency_key
FROM public.incidents
ORDER BY timestamp DESC
LIMIT 10;
```

Fetch specific incident details including mitigation plan and affected entities:

```sql
SELECT 
    i.incident_id,
    i.attack_classification,
    i.risk_score,
    i.risk_category,
    i.mitigation_plan,
    array_agg(DISTINCT ip.ip_address) AS source_ips,
    array_agg(DISTINCT u.username) AS targeted_users
FROM public.incidents i
LEFT JOIN public.incident_source_ips ip ON i.id = ip.incident_id
LEFT JOIN public.incident_user_identifiers u ON i.id = u.incident_id
WHERE i.incident_id = '<INCIDENT_ID>'
GROUP BY i.id;
```

### Step 2: Query Raw Security Logs in Elasticsearch

Query raw logs associated with the incident time window and identified source IP:

```bash
curl -s -k -u "elastic:${ZYLAR_ELASTICSEARCH_PASSWORD}" \
  "https://127.0.0.1:9200/security-events-*/_search?pretty" \
  -H "Content-Type: application/json" -d '{
    "query": {
      "bool": {
        "must": [
          {"term": {"source_ip": "<SOURCE_IP>"}},
          {"range": {"timestamp": {"gte": "now-2h", "lte": "now"}}}
        ]
      }
    },
    "sort": [{"timestamp": {"order": "desc"}}],
    "size": 50
  }'
```

### Step 3: Extract Threat Correlation Graph

Generate the bounded NetworkX correlation graph for the incident context using the Zylar API:

```bash
# Obtain Bearer token
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/token \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"admin\", \"password\": \"${ZYLAR_BOOTSTRAP_ADMIN_PASSWORD}\"}" \
  | jq -r .access_token)

# Fetch correlation graph in Graphviz DOT format
curl -s -X GET "http://127.0.0.1:8000/api/threat-graph?minutes=30&max_events=200" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

---

## 3. Containment & Mitigation Procedures

1. **Firewall / Perimeter Block**:
   Apply perimeter block on external attacker IP:
   ```bash
   # Example iptables block command
   iptables -I INPUT -s <ATTACKER_IP> -j DROP
   ```
2. **Account Disablement**:
   If user credentials were compromised (e.g., in a brute-force or ransomware attack), disable the user account via administrative interface or database:
   ```sql
   UPDATE public.users 
   SET disabled = TRUE, updated_at = NOW() 
   WHERE username = '<COMPROMISED_USER>';
   ```
3. **Record Action in Audit Log**:
   Every analyst intervention must be recorded in `audit_logs`:
   ```sql
   INSERT INTO public.audit_logs (action, actor, details, created_at)
   VALUES (
     'INCIDENT_MITIGATION_APPLIED',
     'analyst_alice',
     '{"incident_id": "<INCIDENT_ID>", "actions": ["ip_blocked", "account_disabled"]}',
     NOW()
   );
   ```

---

## 4. Post-Incident Review Checklist

- [ ] Confirm all compromised hosts have been isolated from production VLAN.
- [ ] Verify that dead-letter queue (`dead_letter_events`) does not contain unprocessed attack telemetry.
- [ ] Validate that all firewall drop rules and account disables are verified by secondary analyst.
- [ ] Archive PDF / JSON investigation report from `reports/` directory.
- [ ] Conduct blameless retrospective within 48 hours for all P1/P2 incidents.

