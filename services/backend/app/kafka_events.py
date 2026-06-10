import asyncio
import json
from typing import Any
from uuid import UUID

from kafka import KafkaProducer
from kafka.errors import KafkaError

from app.config import Settings

EVENT_TYPE_ZERO_DAY_ALERT_RECEIVED = "ZeroDayAlertReceived"


class AlertEventPublisher:
    def __init__(self, settings: Settings) -> None:
        self._topic = settings.kafka_topic_alerts
        # KafkaProducer.__init__ is blocking — call this from a background thread
        # (via asyncio.to_thread) or at startup before the event loop is running.
        self._producer = KafkaProducer(
            bootstrap_servers=settings.kafka_brokers.split(","),
            value_serializer=lambda value: json.dumps(
                value, separators=(",", ":")
            ).encode("utf-8"),
            key_serializer=lambda key: str(key).encode("utf-8") if key else None,
            acks=1,
            linger_ms=0,
            # Tight connection timeout so a mis-configured broker fails fast.
            request_timeout_ms=5_000,
            connections_max_idle_ms=10_000,
        )

    def _publish_sync(self, alert_id: UUID, payload: dict[str, Any]) -> None:
        """Synchronous publish — call this inside asyncio.to_thread."""
        event = {
            "event_type": EVENT_TYPE_ZERO_DAY_ALERT_RECEIVED,
            "alert_id": str(alert_id),
            "payload": payload,
        }
        try:
            future = self._producer.send(
                self._topic, key=str(alert_id), value=event
            )
            # Shorter timeout so the webhook doesn't hang for 10 s if Kafka is slow.
            future.get(timeout=5)
        except KafkaError as exc:
            # Log and swallow — the alert is already in ClickHouse;
            # missing the Kafka event means the worker won't pick it up,
            # but the HTTP layer should still respond 202.
            import sys
            print(f"[kafka_events] WARNING: Kafka publish failed: {exc}", file=sys.stderr)

    async def publish_zero_day_alert_received(
        self, alert_id: UUID, payload: dict[str, Any]
    ) -> None:
        """Async-safe publish: runs the blocking send in a thread pool."""
        await asyncio.to_thread(self._publish_sync, alert_id, payload)

    def close(self) -> None:
        self._producer.flush()
        self._producer.close()
