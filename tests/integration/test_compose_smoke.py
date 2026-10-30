"""Tests for Docker Compose configuration, network isolation, service dependencies, and container definitions."""

import shutil
import subprocess
from pathlib import Path

import yaml  # type: ignore[import-untyped]


def test_compose_config_validates_cleanly():
    """Validates compose.yaml structure, services, and health conditions."""
    compose_path = Path("compose.yaml")
    assert compose_path.exists(), "compose.yaml must exist at repository root"

    with open(compose_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    services = data.get("services", {})
    assert "migration" in services, "compose must define a one-shot migration service"
    assert "api" in services, "compose must define api service"
    assert "worker" in services, "compose must define worker service"
    assert "postgres" in services, "compose must define postgres service"
    assert "elasticsearch" in services, "compose must define elasticsearch service"
    assert "dashboard" in services, "compose must define dashboard service"

    # Migration one-shot contract
    migration = services["migration"]
    assert str(migration.get("restart", "")).lower() in ("no", "never"), "migration must not restart automatically"
    mig_deps = migration.get("depends_on", {})
    assert "postgres" in mig_deps
    assert mig_deps["postgres"].get("condition") == "service_healthy"

    # API depends on migration completing successfully and DB/ES healthy
    api = services["api"]
    deps = api.get("depends_on", {})
    assert "migration" in deps
    assert deps["migration"].get("condition") == "service_completed_successfully"
    assert "postgres" in deps
    assert deps["postgres"].get("condition") == "service_healthy"
    assert "elasticsearch" in deps
    assert deps["elasticsearch"].get("condition") == "service_healthy"

    # Worker depends on migration completing successfully and DB/ES healthy
    worker = services["worker"]
    worker_deps = worker.get("depends_on", {})
    assert "migration" in worker_deps
    assert worker_deps["migration"].get("condition") == "service_completed_successfully"
    assert "postgres" in worker_deps
    assert worker_deps["postgres"].get("condition") == "service_healthy"
    assert "elasticsearch" in worker_deps
    assert worker_deps["elasticsearch"].get("condition") == "service_healthy"
    assert "ports" not in worker or len(worker["ports"]) == 0, "Worker must not publish host ports"

    # Dashboard depends on API healthy
    dashboard = services["dashboard"]
    dash_deps = dashboard.get("depends_on", {})
    assert "api" in dash_deps
    assert dash_deps["api"].get("condition") == "service_healthy"

    # Port binding security: all published ports must be bound to 127.0.0.1
    for svc_name, svc_cfg in services.items():
        ports = svc_cfg.get("ports", [])
        for port_entry in ports:
            port_str = str(port_entry)
            assert port_str.startswith("127.0.0.1:"), (
                f"Service {svc_name} port {port_str} must bind to 127.0.0.1"
            )

    # Network isolation
    networks = data.get("networks", {})
    assert "zylar-frontend" in networks
    assert "zylar-backend" in networks

    api_nets = api.get("networks", [])
    assert "zylar-frontend" in api_nets
    assert "zylar-backend" in api_nets

    worker_nets = worker.get("networks", [])
    assert "zylar-backend" in worker_nets
    assert "zylar-frontend" not in worker_nets, "Worker must not be on the frontend network"

    dash_nets = dashboard.get("networks", [])
    assert "zylar-frontend" in dash_nets
    assert "zylar-backend" not in dash_nets, "Dashboard must not be on the backend network"

    pg_nets = services["postgres"].get("networks", [])
    assert "zylar-backend" in pg_nets
    assert "zylar-frontend" not in pg_nets, "Postgres must not be on the frontend network"

    es_nets = services["elasticsearch"].get("networks", [])
    assert "zylar-backend" in es_nets
    assert "zylar-frontend" not in es_nets, "Elasticsearch must not be on the frontend network"


def test_dockerfiles_enforce_non_root_user():
    """Validates that Dockerfiles for API, Worker, and Dashboard run as non-root user."""
    dockerfiles = [
        Path("docker/Dockerfile.api"),
        Path("docker/Dockerfile.worker"),
        Path("docker/Dockerfile.dashboard"),
    ]
    for df_path in dockerfiles:
        assert df_path.exists(), f"{df_path} must exist"
        content = df_path.read_text(encoding="utf-8")
        assert "USER " in content, f"{df_path} must declare non-root USER instruction"
        assert "USER root" not in content.splitlines()[-1], (
            f"{df_path} must not run as root"
        )


def test_compose_cli_validation_if_available():
    """Executes docker-compose config if installed to verify compose syntax against Docker engine."""
    cmd = None
    if shutil.which("docker-compose"):
        cmd = ["docker-compose", "config"]
    elif shutil.which("docker"):
        cmd = ["docker", "compose", "config"]

    if cmd:
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, f"compose config failed:\n{res.stderr}"
