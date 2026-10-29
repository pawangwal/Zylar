"""Generates the deterministic, versioned synthetic evaluation corpus for Zylar SOC detection rules.

Corpus Version: 2026.10.1
Total Scenarios: 150
  - 100 Benign scenarios (expected_attack=False)
  - 20 Brute Force attacks (expected_attack=True, expected_rule="RULE_BRUTE_FORCE_AUTH")
  - 20 Port Scan attacks (expected_attack=True, expected_rule="RULE_PORT_SCAN_REJECT")
  - 10 Ransomware attacks (expected_attack=True, expected_rule="RULE_RANSOMWARE_INDICATOR")
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

CORPUS_VERSION: str = "2026.10.1"
BASE_TIMESTAMP = datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC)


def generate_corpus() -> dict[str, Any]:
    scenarios: list[dict[str, Any]] = []

    # ---------------------------------------------------------
    # 1. 100 Benign Scenarios
    # ---------------------------------------------------------
    benign_users = ["alice", "bob", "charlie", "david", "emma", "frank", "grace", "heidi"]
    benign_ips = [f"192.168.1.{i}" for i in range(10, 30)]

    for idx in range(100):
        scenario_id = f"scenario-benign-{idx + 1:03d}"
        user = benign_users[idx % len(benign_users)]
        src_ip = benign_ips[idx % len(benign_ips)]
        events: list[dict[str, Any]] = []

        if idx < 25:
            # Web browsing traffic
            desc = f"Normal web application navigation by {user}"
            for step in range(3):
                events.append({
                    "event_id": f"{scenario_id}-ev-{step}",
                    "timestamp": (BASE_TIMESTAMP + timedelta(seconds=idx * 60 + step * 5)).isoformat(),
                    "event_type": "web_access",
                    "source_ip": src_ip,
                    "user": user,
                    "status": "success",
                    "destination_port": 443 if step % 2 == 0 else 80,
                    "details": f"GET /app/dashboard/view_{step} HTTP/1.1 200 OK",
                })
        elif idx < 50:
            # Internal service-to-service communication
            desc = f"Internal microservice RPC calls from {src_ip}"
            for step in range(4):
                events.append({
                    "event_id": f"{scenario_id}-ev-{step}",
                    "timestamp": (BASE_TIMESTAMP + timedelta(seconds=idx * 60 + step * 2)).isoformat(),
                    "event_type": "api_call",
                    "source_ip": src_ip,
                    "user": f"service-{user}",
                    "status": "success",
                    "destination_port": 5432 if step == 0 else 8080,
                    "details": f"Internal query customer_record_{step}",
                })
        elif idx < 70:
            # Low-volume auth: 1 success or 1-3 failed attempts (well below the 5-failure threshold)
            fail_count = (idx % 3) + 1  # 1, 2, or 3 attempts
            desc = f"User {user} mistyping password ({fail_count} failed attempts, below brute force threshold)"
            for step in range(fail_count):
                events.append({
                    "event_id": f"{scenario_id}-ev-{step}",
                    "timestamp": (BASE_TIMESTAMP + timedelta(seconds=idx * 60 + step * 10)).isoformat(),
                    "event_type": "authentication",
                    "source_ip": src_ip,
                    "user": user,
                    "status": "failed",
                    "destination_port": 22,
                    "details": f"Authentication failure attempt {step + 1} for {user}",
                })
            # Followed by a successful login
            events.append({
                "event_id": f"{scenario_id}-ev-{fail_count}",
                "timestamp": (BASE_TIMESTAMP + timedelta(seconds=idx * 60 + fail_count * 10 + 5)).isoformat(),
                "event_type": "authentication",
                "source_ip": src_ip,
                "user": user,
                "status": "success",
                "destination_port": 22,
                "details": f"Authentication success for {user}",
            })
        elif idx < 85:
            # Routine administrative maintenance
            desc = f"Admin maintenance task executed by {user}"
            events.append({
                "event_id": f"{scenario_id}-ev-0",
                "timestamp": (BASE_TIMESTAMP + timedelta(seconds=idx * 60)).isoformat(),
                "event_type": "admin_session",
                "source_ip": src_ip,
                "user": user,
                "status": "success",
                "destination_port": 22,
                "details": "SSH session started; sudo systemctl restart nginx",
            })
            events.append({
                "event_id": f"{scenario_id}-ev-1",
                "timestamp": (BASE_TIMESTAMP + timedelta(seconds=idx * 60 + 15)).isoformat(),
                "event_type": "file_write",
                "source_ip": src_ip,
                "user": user,
                "status": "success",
                "destination_port": None,
                "details": "Configuration file /etc/nginx/nginx.conf modified and backed up",
            })
        else:
            # Low-volume network probe: 2-4 distinct ports probed (well below 10 unique ports threshold)
            probe_ports = [80, 443, 8080, 8443][: ((idx % 3) + 2)]
            desc = f"Routine network monitoring probe on {len(probe_ports)} ports (below scan threshold)"
            for step, port in enumerate(probe_ports):
                events.append({
                    "event_id": f"{scenario_id}-ev-{step}",
                    "timestamp": (BASE_TIMESTAMP + timedelta(seconds=idx * 60 + step * 4)).isoformat(),
                    "event_type": "network",
                    "source_ip": src_ip,
                    "user": "nagios-monitor",
                    "status": "rejected",
                    "destination_port": port,
                    "details": f"TCP SYN to port {port} rejected",
                })

        scenarios.append({
            "scenario_id": scenario_id,
            "label": "benign",
            "expected_attack": False,
            "expected_rule": None,
            "description": desc,
            "events": events,
        })

    # ---------------------------------------------------------
    # 2. 20 Brute Force Attack Scenarios
    # ---------------------------------------------------------
    for idx in range(20):
        scenario_id = f"scenario-attack-bf-{idx + 1:03d}"
        target_user = "root" if idx % 2 == 0 else "admin"
        attacker_ip = f"198.51.100.{40 + idx}"
        attempt_count = 5 + (idx % 6)  # 5 to 10 attempts
        port = 22 if idx < 12 else (3389 if idx < 16 else 443)
        event_type = "authentication" if port != 443 else "login"

        events = []
        for step in range(attempt_count):
            events.append({
                "event_id": f"{scenario_id}-ev-{step}",
                "timestamp": (BASE_TIMESTAMP + timedelta(minutes=120 + idx * 5, seconds=step * 3)).isoformat(),
                "event_type": event_type,
                "source_ip": attacker_ip,
                "user": target_user,
                "status": "failed",
                "destination_port": port,
                "details": f"Failed password attempt {step + 1} for user {target_user} from {attacker_ip}",
            })

        scenarios.append({
            "scenario_id": scenario_id,
            "label": "brute_force",
            "expected_attack": True,
            "expected_rule": "RULE_BRUTE_FORCE_AUTH",
            "description": f"Automated brute-force password spraying against {target_user} on port {port} ({attempt_count} failures in < 60s)",
            "events": events,
        })

    # ---------------------------------------------------------
    # 3. 20 Port Scan Attack Scenarios
    # ---------------------------------------------------------
    all_scan_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
    ]
    for idx in range(20):
        scenario_id = f"scenario-attack-ps-{idx + 1:03d}"
        attacker_ip = f"203.0.113.{50 + idx}"
        port_count = 10 + (idx % 12)  # 10 to 21 distinct ports
        selected_ports = all_scan_ports[:port_count]

        events = []
        for step, port in enumerate(selected_ports):
            events.append({
                "event_id": f"{scenario_id}-ev-{step}",
                "timestamp": (BASE_TIMESTAMP + timedelta(minutes=240 + idx * 5, seconds=step * 2)).isoformat(),
                "event_type": "network",
                "source_ip": attacker_ip,
                "user": "unknown",
                "status": "rejected",
                "destination_port": port,
                "details": f"TCP SYN connection to port {port} rejected by firewall",
            })

        scenarios.append({
            "scenario_id": scenario_id,
            "label": "port_scan",
            "expected_attack": True,
            "expected_rule": "RULE_PORT_SCAN_REJECT",
            "description": f"Vertical network reconnaissance scan probing {port_count} distinct ports in < 60s",
            "events": events,
        })

    # ---------------------------------------------------------
    # 4. 10 Ransomware Attack Scenarios
    # ---------------------------------------------------------
    for idx in range(10):
        scenario_id = f"scenario-attack-rw-{idx + 1:03d}"
        victim_ip = f"10.0.0.{100 + idx}"
        victim_user = f"victim_user_{idx + 1}"

        if idx < 5:
            detail_msg = f"Rapid mass rename of 600 files to .locked extension; ransom note README_DECRYPT_{idx}.txt written"
            etype = "ransomware"
        elif idx < 8:
            detail_msg = "File system alert: 450 documents modified with .encrypted suffix and entropy > 7.9"
            etype = "file_system"
        else:
            detail_msg = "Volume shadow copies deleted via vssadmin.exe delete shadows /all /quiet; ransomware payload executed"
            etype = "ransomware"

        events = [
            {
                "event_id": f"{scenario_id}-ev-0",
                "timestamp": (BASE_TIMESTAMP + timedelta(minutes=360 + idx * 10)).isoformat(),
                "event_type": etype,
                "source_ip": victim_ip,
                "user": victim_user,
                "status": "failure",
                "destination_port": None,
                "details": detail_msg,
            }
        ]

        scenarios.append({
            "scenario_id": scenario_id,
            "label": "ransomware",
            "expected_attack": True,
            "expected_rule": "RULE_RANSOMWARE_INDICATOR",
            "description": f"Ransomware activity on {victim_ip} ({victim_user}): {detail_msg}",
            "events": events,
        })

    return {
        "corpus_version": CORPUS_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "total_scenarios": len(scenarios),
        "breakdown": {
            "benign": 100,
            "brute_force": 20,
            "port_scan": 20,
            "ransomware": 10,
        },
        "scenarios": scenarios,
    }


def write_corpus(output_path: Path | None = None) -> Path:
    if output_path is None:
        output_path = Path(__file__).parents[1] / "tests" / "fixtures" / "synthetic_evaluation_corpus.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    corpus = generate_corpus()
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=2)
    return output_path


if __name__ == "__main__":
    out = write_corpus()
    print(f"Synthetic evaluation corpus written to: {out} (Total scenarios: 150)")
