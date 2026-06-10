#!/usr/bin/env python3
"""
Phase 1 infrastructure verification for ZIA.

Checks ClickHouse (HTTP + native), Redpanda broker, Neo4j Bolt,
and that ClickHouse schema tables exist.
"""

from __future__ import annotations

import os
import socket
import time

import requests
from clickhouse_driver import Client
from neo4j import GraphDatabase, basic_auth

EXPECTED_TABLES = frozenset(
    {
        "zero_day_alerts",
        "enrichment_evidence",
        "agent_events",
        "token_usage",
        "alert_links",
    }
)

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_HTTP_PORT = int(os.getenv("CLICKHOUSE_HTTP_PORT", "8123"))
CLICKHOUSE_NATIVE_PORT = int(os.getenv("CLICKHOUSE_NATIVE_PORT", "9000"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "zia")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "zia")

REDPANDA_BROKERS = os.getenv("REDPANDA_BROKERS", "localhost:19092")
REDPANDA_ADMIN_URL = os.getenv("REDPANDA_ADMIN_URL", "http://localhost:9644")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "zia_dev_password")

MAX_WAIT_SEC = int(os.getenv("ZIA_VERIFY_MAX_WAIT_SEC", "120"))
POLL_INTERVAL_SEC = float(os.getenv("ZIA_VERIFY_POLL_INTERVAL_SEC", "3"))


def _log(msg: str) -> None:
    print(msg, flush=True)


def _wait_until(label: str, fn, max_wait: int = MAX_WAIT_SEC) -> None:
    deadline = time.monotonic() + max_wait
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            fn()
            _log(f"  OK  {label}")
            return
        except Exception as exc:  # noqa: BLE001 — retry loop
            last_error = exc
            time.sleep(POLL_INTERVAL_SEC)
    raise RuntimeError(f"{label} failed after {max_wait}s: {last_error}") from last_error


def verify_clickhouse_http() -> None:
    url = f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_HTTP_PORT}/ping"
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    if response.text.strip() != "Ok.":
        raise RuntimeError(f"unexpected ping body: {response.text!r}")


def verify_clickhouse_native_and_schema() -> set[str]:
    client = Client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_NATIVE_PORT,
        user=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE,
        connect_timeout=5,
        send_receive_timeout=10,
    )
    client.execute("SELECT 1")
    rows = client.execute("SHOW TABLES")
    tables = {row[0] for row in rows}
    missing = EXPECTED_TABLES - tables
    if missing:
        raise RuntimeError(f"missing tables in {CLICKHOUSE_DATABASE}: {sorted(missing)}")
    return tables


def verify_redpanda() -> None:
    # Kafka listener (TCP)
    broker = REDPANDA_BROKERS.split(",")[0].strip()
    host, _, port_str = broker.partition(":")
    port = int(port_str or "9092")
    with socket.create_connection((host, port), timeout=5):
        pass

    # Admin API (cluster health)
    response = requests.get(f"{REDPANDA_ADMIN_URL.rstrip('/')}/v1/brokers", timeout=5)
    response.raise_for_status()
    brokers = response.json()
    if not brokers:
        raise RuntimeError("Redpanda admin API returned no brokers")


def verify_neo4j() -> None:
    driver = GraphDatabase.driver(NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            record = session.run("RETURN 1 AS n").single()
            if record is None or record["n"] != 1:
                raise RuntimeError("unexpected RETURN 1 result")
    finally:
        driver.close()


def main() -> int:
    _log("ZIA Phase 1 — infrastructure verification")
    _log(f"  ClickHouse: {CLICKHOUSE_HOST}:{CLICKHOUSE_HTTP_PORT} (http), :{CLICKHOUSE_NATIVE_PORT} (native)")
    _log(f"  Redpanda:   {REDPANDA_BROKERS}")
    _log(f"  Neo4j:      {NEO4J_URI}")

    _wait_until("ClickHouse HTTP /ping", verify_clickhouse_http)

    tables: set[str] = set()

    def _native_and_schema() -> None:
        nonlocal tables
        tables = verify_clickhouse_native_and_schema()

    _wait_until("ClickHouse native + schema", _native_and_schema)
    _wait_until("Redpanda broker", verify_redpanda)
    _wait_until("Neo4j Bolt", verify_neo4j)

    _log("")
    _log("All checks passed.")
    _log(f"  ClickHouse tables ({CLICKHOUSE_DATABASE}): {', '.join(sorted(tables))}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        _log(f"\nFAILED: {exc}")
        raise SystemExit(1) from exc
