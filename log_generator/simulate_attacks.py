from __future__ import annotations

import datetime
import random
import time
import uuid
from typing import Any, Dict, List, Optional
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from zylar.core.settings import get_settings

# Configure Elasticsearch from the application settings.
settings = get_settings()
ES_HOST = str(settings.elasticsearch_url).rstrip("/")
INDEX_NAME = settings.elasticsearch_index

es = Elasticsearch(**settings.elasticsearch_client_kwargs)


def setup_index():
    """Create the index if it doesn't exist."""
    try:
        es.indices.create(index=INDEX_NAME)
        print(f"Created index: {INDEX_NAME}")
    except Exception:
        # Index already exists or error
        pass


def generate_log(
    event_type: str,
    ip: str,
    user: str,
    status: str,
    details: str,
    destination_port: Optional[int] = None,
    timestamp: Optional[datetime.datetime] = None,
    event_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Helper to structure a canonical log document."""
    ts = (timestamp or datetime.datetime.now(datetime.timezone.utc)).isoformat()
    if not ts.endswith("Z") and "+" not in ts:
        ts = ts + "Z"

    source_doc: Dict[str, Any] = {
        "timestamp": ts,
        "event_id": event_id or str(uuid.uuid4()),
        "event_type": event_type,
        "source_ip": ip,
        "user": user,
        "status": status,
        "details": details,
    }

    if destination_port is not None:
        source_doc["destination_port"] = destination_port

    return {
        "_index": INDEX_NAME,
        "_source": source_doc,
    }


def simulate_brute_force(ip: str, user: str, count: int = 15) -> List[Dict[str, Any]]:
    """Generate multiple failed login attempts followed perhaps by a success."""
    logs = []
    for _ in range(count):
        logs.append(
            generate_log(
                "authentication",
                ip,
                user,
                "failed",
                "Invalid credentials",
                destination_port=22,
            )
        )
        time.sleep(0.01)
    return logs


def simulate_port_scan(ip: str) -> List[Dict[str, Any]]:
    """Generate connection attempts to multiple unusual ports sequentially."""
    logs = []
    ports = random.sample(range(1, 1024), 20)
    for port in ports:
        logs.append(
            generate_log(
                "network",
                ip,
                "system",
                "rejected",
                f"Connection attempt to closed port {port}",
                destination_port=port,
            )
        )
        time.sleep(0.01)
    return logs


def simulate_ransomware_access(ip: str, user: str) -> List[Dict[str, Any]]:
    """Generate high volume of file read/write/encrypt operations."""
    logs = []
    for i in range(25):
        ext = random.choice([".doc", ".pdf", ".xls", ".jpg"])
        logs.append(
            generate_log(
                "file_access",
                ip,
                user,
                "success",
                f"File modified: /shared/docs/file_{i}{ext}.encrypted",
                destination_port=445,
            )
        )
        time.sleep(0.01)
    return logs


def simulate_normal_activity() -> List[Dict[str, Any]]:
    """Generate standard web access or safe login."""
    users = ["alice", "bob", "charlie", "david"]
    ips = [f"192.168.1.{random.randint(10, 50)}" for _ in range(5)]
    port = random.choice([80, 443])
    return [
        generate_log(
            "web_access",
            random.choice(ips),
            random.choice(users),
            "success",
            f"Accessed page {random.choice(['/home', '/dashboard', '/profile', '/api/data'])}",
            destination_port=port,
        )
    ]


def simulate_suspicious_ip_activity() -> List[Dict[str, Any]]:
    """Activity from a known bad IP subnet or strange geo (simulated by IP string)."""
    malicious_ip = f"185.15.{random.randint(1, 255)}.{random.randint(1, 255)}"
    return [
        generate_log(
            "authentication",
            malicious_ip,
            "admin",
            "failed",
            "Geo-policy violation",
            destination_port=22,
        )
    ]


# -------------------------------------------------------------------------
# Deterministic fixture generators for reproducible tests and benchmarking
# -------------------------------------------------------------------------

def generate_deterministic_benign_events(
    count: int = 10,
    base_time: Optional[datetime.datetime] = None,
) -> List[Dict[str, Any]]:
    """Generates immutable deterministic benign web access events."""
    t0 = base_time or datetime.datetime(2026, 10, 25, 12, 0, 0, tzinfo=datetime.timezone.utc)
    users = ["alice", "bob", "charlie"]
    ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    events = []
    for i in range(count):
        ts = t0 + datetime.timedelta(seconds=i * 10)
        events.append(
            generate_log(
                event_type="web_access",
                ip=ips[i % len(ips)],
                user=users[i % len(users)],
                status="success",
                details=f"GET /dashboard/view_{i % 3}",
                destination_port=443,
                timestamp=ts,
                event_id=f"benign-{i:04d}",
            )["_source"]
        )
    return events


def generate_deterministic_brute_force(
    ip: str = "198.51.100.22",
    user: str = "root",
    count: int = 15,
    base_time: Optional[datetime.datetime] = None,
) -> List[Dict[str, Any]]:
    """Generates immutable deterministic brute force attack events."""
    t0 = base_time or datetime.datetime(2026, 10, 25, 12, 10, 0, tzinfo=datetime.timezone.utc)
    events = []
    for i in range(count):
        ts = t0 + datetime.timedelta(seconds=i * 2)
        events.append(
            generate_log(
                event_type="authentication",
                ip=ip,
                user=user,
                status="failed",
                details=f"Failed SSH password attempt {i + 1}",
                destination_port=22,
                timestamp=ts,
                event_id=f"bf-{i:04d}",
            )["_source"]
        )
    return events


def generate_deterministic_port_scan(
    ip: str = "203.0.113.45",
    ports: Optional[List[int]] = None,
    base_time: Optional[datetime.datetime] = None,
) -> List[Dict[str, Any]]:
    """Generates immutable deterministic port scan events across structured destination ports."""
    t0 = base_time or datetime.datetime(2026, 10, 25, 12, 20, 0, tzinfo=datetime.timezone.utc)
    target_ports = ports or [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080]
    events = []
    for i, port in enumerate(target_ports):
        ts = t0 + datetime.timedelta(milliseconds=i * 200)
        events.append(
            generate_log(
                event_type="network",
                ip=ip,
                user="system",
                status="rejected",
                details=f"SYN packet rejected on port {port}",
                destination_port=port,
                timestamp=ts,
                event_id=f"ps-{i:04d}",
            )["_source"]
        )
    return events


def generate_deterministic_ransomware(
    ip: str = "10.0.0.99",
    user: str = "compromised_user",
    count: int = 25,
    base_time: Optional[datetime.datetime] = None,
) -> List[Dict[str, Any]]:
    """Generates immutable deterministic ransomware activity events."""
    t0 = base_time or datetime.datetime(2026, 10, 25, 12, 30, 0, tzinfo=datetime.timezone.utc)
    events = []
    for i in range(count):
        ts = t0 + datetime.timedelta(milliseconds=i * 50)
        events.append(
            generate_log(
                event_type="file_access",
                ip=ip,
                user=user,
                status="success",
                details=f"File modified: /shared/docs/finance_{i}.xlsx.encrypted",
                destination_port=445,
                timestamp=ts,
                event_id=f"rw-{i:04d}",
            )["_source"]
        )
    return events


def run_simulation(duration_seconds: int = 60, batch_size: int = 1):
    """Runs a continuous stream of logs mixing normal and attack activity."""
    setup_index()
    print(f"Starting simulation for {duration_seconds} seconds...")
    start_time = time.time()

    attack_ips = ["203.0.113.45", "198.51.100.22", "10.0.0.99"]
    users = ["root", "admin", "service_account"]

    while time.time() - start_time < duration_seconds:
        logs_to_push = []

        # 80% normal activity, 20% attacks
        if random.random() < 0.8:
            for _ in range(batch_size):
                logs_to_push.extend(simulate_normal_activity())
        else:
            attack_type = random.choice(["brute_force", "port_scan", "ransomware", "suspicious_ip"])
            if attack_type == "brute_force":
                logs_to_push.extend(
                    simulate_brute_force(
                        random.choice(attack_ips), random.choice(users), random.randint(10, 30)
                    )
                )
            elif attack_type == "port_scan":
                logs_to_push.extend(simulate_port_scan(random.choice(attack_ips)))
            elif attack_type == "ransomware":
                logs_to_push.extend(
                    simulate_ransomware_access(random.choice(attack_ips), "compromised_user")
                )
            elif attack_type == "suspicious_ip":
                logs_to_push.extend(simulate_suspicious_ip_activity())

        # Push to Elasticsearch
        if logs_to_push:
            try:
                bulk(es, logs_to_push)
                print(
                    f"Pushed {len(logs_to_push)} logs. Timestamp: {datetime.datetime.now(datetime.timezone.utc).time()}"
                )
            except Exception as e:
                print(f"Error pushing logs: {e}")

        time.sleep(random.uniform(0.5, 2.0))

    print("Simulation finished.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--duration", type=int, default=300, help="Duration to run simulation in seconds"
    )
    args = parser.parse_args()

    run_simulation(args.duration)
