# ELK Setup for ZYLAR

This directory contains the configuration to run a local Elasticsearch and Kibana instance using Docker Compose.

> [!IMPORTANT]
> **Security Boundary Notice:**
> The Docker Compose configuration in this directory is strictly intended for **local development and testing**. 
> - Host published ports bind exclusively to loopback (`127.0.0.1:9200` and `127.0.0.1:5601`) to prevent external network exposure.
> - Security is disabled (`xpack.security.enabled=false`) to simplify local friction-free test runs.
> - **Production Deployment Requirements:** In any production or shared container environment, disabling Elasticsearch security is prohibited. Production deployments must:
>   1. Enable X-Pack security (`xpack.security.enabled=true`).
>   2. Configure TLS encryption for internal cluster transport and external HTTP traffic.
>   3. Enforce authenticated access with strong credentials injected via secrets into `ZYLAR_ELASTICSEARCH_URL` (e.g. `https://zylar_app:strong-password@es01:9200`).
>   4. Isolate Docker networks so untrusted containers cannot access the cluster directly.

## Prerequisites
- Docker
- Docker Compose

## Starting the Stack
Navigate to this directory and run:

```bash
docker-compose up -d
```

Elasticsearch will be available at `http://127.0.0.1:9200`.
Kibana will be available at `http://127.0.0.1:5601`.

## Stopping the Stack
```bash
docker-compose down
```

To remove all retained data:
```bash
docker-compose down -v
```
