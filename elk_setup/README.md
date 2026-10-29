# ELK Setup for ZYLAR

This directory contains the configuration to run a local Elasticsearch and Kibana instance using Docker Compose.

> [!IMPORTANT]
> **Security Boundary Notice:**
> The Docker Compose configuration in this directory is intended for **local development and testing**. 
> - Host published ports bind exclusively to loopback (`127.0.0.1:9200` and `127.0.0.1:5601`) to prevent external network exposure.
> - Authentication is enabled (`xpack.security.enabled=true`) using direct password authentication via `ZYLAR_ELASTICSEARCH_PASSWORD`.
> - **Production Deployment Requirements:** In any production or shared container environment across multiple hosts:
>   1. Configure TLS encryption for internal cluster transport and external HTTP traffic.
>   2. Enforce fine-grained least-privilege roles for ingestion workers and simulators rather than using the default administrative account.
>   3. Isolate Docker networks so untrusted containers cannot access the cluster directly.

## Prerequisites
- Docker
- Docker Compose

## Starting the Stack
1. Ensure `ZYLAR_ELASTICSEARCH_PASSWORD` is configured in your root `.env` file.
2. From the repository root, start the stack:
   ```powershell
   docker compose --env-file .env -f elk_setup/docker-compose.yml up -d
   ```
   *(Or navigate into `elk_setup` and run `docker compose up -d`)*

Elasticsearch will be available at `http://127.0.0.1:9200` (Basic Auth user `elastic`).
Kibana will be available at `http://127.0.0.1:5601` (Login with `elastic` and your configured password).

## Stopping the Stack
```bash
docker compose down
```

To remove all retained data (CAUTION: destroys Elasticsearch indices):
```bash
docker compose down -v
```
