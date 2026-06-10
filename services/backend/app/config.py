import os
from functools import lru_cache


@lru_cache
def get_settings() -> "Settings":
    return Settings()


class Settings:
    # Do NOT hardcode secrets. Require explicit environment value.
    webhook_secret: str = os.getenv("WEBHOOK_SECRET", "")
    clickhouse_host: str = os.getenv("CLICKHOUSE_HOST", "localhost")
    clickhouse_port: int = int(os.getenv("CLICKHOUSE_PORT", "9000"))
    clickhouse_user: str = os.getenv("CLICKHOUSE_USER", "zia")
    clickhouse_password: str = os.getenv("CLICKHOUSE_PASSWORD", "")
    clickhouse_database: str = os.getenv("CLICKHOUSE_DATABASE", "zia")
    kafka_brokers: str = os.getenv("REDPANDA_BROKERS", "localhost:19092")
    kafka_topic_alerts: str = os.getenv("KAFKA_TOPIC_ALERTS", "zeroday.alerts.v1")
    default_tenant_id: str = os.getenv("DEFAULT_TENANT_ID", "default")
