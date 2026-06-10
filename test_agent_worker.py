from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from clickhouse_driver import Client as ClickHouseClient
from kafka import KafkaProducer
from neo4j import GraphDatabase, basic_auth

EVENT_TYPE_ZERO_DAY_ALERT_RECEIVED = "ZeroDayAlertReceived"

KAFKA_BROKERS = os.getenv("REDPANDA_BROKERS", "localhost:19092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC_ALERTS", "zeroday.alerts.v1")

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "zia")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "zia")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "zia_dev_password")


def _producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BROKERS.split(","),
        value_serializer=lambda v: json.dumps(v, separators=(",", ":")).encode("utf-8"),
        key_serializer=lambda k: str(k).encode("utf-8") if k else None,
        acks=1,
    )


def _clickhouse() -> ClickHouseClient:
    return ClickHouseClient(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        user=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE,
    )


def _publish_mock_alert(alert_id: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tenant_id": "demo-tenant",
        "title": "Log4Shell exploit observed in perimeter logs",
        "source": "phase4-test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "cve": "CVE-2021-44228",
            "src_ip": "198.51.100.10",
            "dst_domain": "prod.example.com",
            "url": "https://attacker.example/poc",
            "product": "Apache Log4j",
            "version": "2.14.1",
        },
        "actors": ["APT29"],
    }
    event = {
        "event_type": EVENT_TYPE_ZERO_DAY_ALERT_RECEIVED,
        "alert_id": alert_id,
        "payload": payload,
    }
    producer = _producer()
    try:
        producer.send(KAFKA_TOPIC, key=alert_id, value=event).get(timeout=10)
        producer.flush()
    finally:
        producer.close()
    return payload


def _wait_for_completed(ch: ClickHouseClient, alert_id: str, timeout_sec: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        rows = ch.execute(
            """
            SELECT status
            FROM zero_day_alerts
            WHERE alert_id = %(id)s
            ORDER BY row_version DESC
            LIMIT 1
            """,
            {"id": uuid.UUID(alert_id)},
        )
        if rows and rows[0][0] == "COMPLETED":
            return
        time.sleep(1.0)
    raise AssertionError(f"Alert {alert_id} did not reach COMPLETED within {timeout_sec}s")


def test_agent_worker_end_to_end() -> None:
    alert_id = str(uuid.uuid4())
    _publish_mock_alert(alert_id)

    ch = _clickhouse()
    _wait_for_completed(ch, alert_id)

    # Verify agent trace logs
    event_rows = ch.execute(
        "SELECT count() FROM agent_events WHERE alert_id = %(id)s",
        {"id": uuid.UUID(alert_id)},
    )
    assert event_rows[0][0] > 0, "Expected agent_events rows for alert"

    # Verify token usage was logged
    usage_rows = ch.execute(
        "SELECT count() FROM token_usage WHERE alert_id = %(id)s",
        {"id": uuid.UUID(alert_id)},
    )
    assert usage_rows[0][0] > 0, "Expected token_usage rows for alert"

    # Verify Neo4j nodes and edges exist
    driver = GraphDatabase.driver(NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            node_count = session.run(
                """
                MATCH (c:Case {id:$case_id})-[:HAS_ENTITY]->(e:Entity)
                RETURN count(e) AS cnt
                """,
                case_id=alert_id,
            ).single()
            assert node_count and node_count["cnt"] > 0, "Expected Entity nodes in Neo4j"

            rel_count = session.run(
                """
                MATCH (:Entity {case_id:$case_id})-[r:RELATED]->(:Entity {case_id:$case_id})
                RETURN count(r) AS cnt
                """,
                case_id=alert_id,
            ).single()
            assert rel_count and rel_count["cnt"] > 0, "Expected RELATED edges in Neo4j"
    finally:
        driver.close()

