"""
Integration tests for POST /api/v1/webhook/zeroday.

Requires the Phase 1/2 stack running (docker compose up).
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

import httpx
import pytest
from clickhouse_driver import Client
from kafka import KafkaConsumer, TopicPartition
from kafka.admin import KafkaAdminClient, NewTopic

API_BASE_URL = os.getenv("ZIA_API_BASE_URL", "http://localhost:8000")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
WEBHOOK_PATH = "/api/v1/webhook/zeroday"
KAFKA_BROKERS = os.getenv("REDPANDA_BROKERS", "localhost:19092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC_ALERTS", "zeroday.alerts.v1")

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "zia")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "zia")

MOCK_PAYLOAD: dict[str, Any] = {
    "title": "Critical OpenSSL vulnerability",
    "severity": "CRITICAL",
    "source": "test-scanner",
    "tenant_id": "demo-tenant",
    "details": {
        "cve": "CVE-2024-1234",
        "indicator": "192.0.2.100",
        "url": "https://evil.example.com/payload",
        "hash": "a" * 64,
    },
}


@pytest.fixture(scope="module")
def http_client() -> httpx.Client:
    headers = {"x-Webhook-Secret": WEBHOOK_SECRET, "Content-Type": "application/json"}
    with httpx.Client(base_url=API_BASE_URL, headers=headers, timeout=10.0) as client:
        health = client.get("/health")
        if health.status_code != 200:
            pytest.skip(f"Backend not reachable at {API_BASE_URL}")
        yield client


@pytest.fixture(scope="module")
def ch_client() -> Client:
    client = Client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        user=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE,
    )
    client.execute("SELECT 1")
    return client


@pytest.fixture(scope="module", autouse=True)
def ensure_kafka_topic() -> None:
    admin = KafkaAdminClient(
        bootstrap_servers=KAFKA_BROKERS.split(","),
        client_id="zia-test-admin",
    )
    try:
        admin.create_topics(
            [NewTopic(name=KAFKA_TOPIC, num_partitions=1, replication_factor=1)],
            validate_only=False,
        )
    except Exception:
        pass
    finally:
        admin.close()


def _post_webhook(client: httpx.Client, payload: dict[str, Any]) -> httpx.Response:
    return client.post(WEBHOOK_PATH, json=payload)


def _wait_for_alert_status(ch: Client, alert_id: str, expected: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = ch.execute(
            "SELECT status FROM zero_day_alerts WHERE alert_id = %(id)s ORDER BY row_version DESC LIMIT 1",
            {"id": uuid.UUID(alert_id)},
        )
        if rows and rows[0][0] == expected:
            return
        time.sleep(0.1)
    raise AssertionError(f"alert {alert_id} never reached status {expected}")


def _consume_event_for_alert(alert_id: str, timeout_sec: float = 15.0) -> dict[str, Any]:
    consumer = KafkaConsumer(
        bootstrap_servers=KAFKA_BROKERS.split(","),
        group_id=f"zia-test-{uuid.uuid4()}",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        consumer_timeout_ms=1000,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    )
    try:
        partitions = consumer.partitions_for_topic(KAFKA_TOPIC)
        if not partitions:
            raise AssertionError(f"topic {KAFKA_TOPIC} has no partitions")
        tps = [TopicPartition(KAFKA_TOPIC, p) for p in partitions]
        consumer.assign(tps)
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            records = consumer.poll(timeout_ms=500)
            for batch in records.values():
                for message in batch:
                    event = message.value
                    if (
                        event.get("event_type") == "ZeroDayAlertReceived"
                        and event.get("alert_id") == alert_id
                    ):
                        return event
        raise AssertionError(
            f"ZeroDayAlertReceived for alert_id={alert_id} not found on {KAFKA_TOPIC}"
        )
    finally:
        consumer.close()


@pytest.fixture(scope="module")
def canonical_alert(http_client: httpx.Client) -> dict[str, Any]:
    """First ingest of MOCK_PAYLOAD; used by downstream tests."""
    _post_webhook(http_client, {"warmup": True, "nonce": str(uuid.uuid4())})
    response = _post_webhook(http_client, MOCK_PAYLOAD)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "RECEIVED"
    assert body["duplicate"] is False
    return body


def test_post_returns_202_under_200ms(
    http_client: httpx.Client, canonical_alert: dict[str, Any]
) -> None:
    unique_payload = {
        **MOCK_PAYLOAD,
        "title": "Latency probe",
        "details": {**MOCK_PAYLOAD["details"], "cve": "CVE-2099-0001"},
    }
    start = time.perf_counter()
    response = _post_webhook(http_client, unique_payload)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert response.status_code == 202, response.text
    assert elapsed_ms < 200, f"expected <200ms, got {elapsed_ms:.1f}ms"
    assert response.json()["status"] == "RECEIVED"


def test_clickhouse_received_status(ch_client: Client, canonical_alert: dict[str, Any]) -> None:
    alert_id = canonical_alert["alert_id"]
    _wait_for_alert_status(ch_client, alert_id, "RECEIVED")
    rows = ch_client.execute(
        """
        SELECT status, length(cve_ids), fingerprint
        FROM zero_day_alerts
        WHERE alert_id = %(id)s
        ORDER BY row_version DESC
        LIMIT 1
        """,
        {"id": uuid.UUID(alert_id)},
    )
    assert rows[0][0] == "RECEIVED"
    assert rows[0][1] >= 1
    assert rows[0][2]


def test_kafka_zero_day_alert_received_event(canonical_alert: dict[str, Any]) -> None:
    event = _consume_event_for_alert(canonical_alert["alert_id"])
    assert event["event_type"] == "ZeroDayAlertReceived"
    assert event["payload"]["title"] == MOCK_PAYLOAD["title"]


def test_duplicate_payload_marked_duplicate(
    http_client: httpx.Client, ch_client: Client, canonical_alert: dict[str, Any]
) -> None:
    response = _post_webhook(http_client, MOCK_PAYLOAD)
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "DUPLICATE"
    assert body["duplicate"] is True
    assert body["canonical_alert_id"] == canonical_alert["alert_id"]

    _wait_for_alert_status(ch_client, body["alert_id"], "DUPLICATE")

    links = ch_client.execute(
        """
        SELECT link_type, target_alert_id
        FROM alert_links
        WHERE source_alert_id = %(src)s
        ORDER BY timestamp DESC
        LIMIT 1
        """,
        {"src": uuid.UUID(body["alert_id"])},
    )
    assert links
    assert links[0][0] == "DUPLICATE"
    assert str(links[0][1]) == canonical_alert["alert_id"]


def test_unauthorized_without_secret() -> None:
    with httpx.Client(base_url=API_BASE_URL, timeout=5.0) as bare:
        response = bare.post(WEBHOOK_PATH, json=MOCK_PAYLOAD)
    assert response.status_code == 401
