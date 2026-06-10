#!/usr/bin/env bash
# Run webhook integration tests inside Docker on the compose network.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose up -d clickhouse redpanda neo4j backend

docker run --rm --network zia_zia-net \
  -v "$(pwd):/app" -w /app \
  -e ZIA_API_BASE_URL=http://backend:8000 \
  -e REDPANDA_BROKERS=redpanda:9092 \
  -e CLICKHOUSE_HOST=clickhouse \
  -e CLICKHOUSE_PORT=9000 \
  -e WEBHOOK_SECRET="${WEBHOOK_SECRET:-}" \
  python:3.12-slim \
  bash -c "pip install -q -r requirements-test.txt && pytest test_webhook.py -v"
