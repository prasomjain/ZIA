-- ZIA ClickHouse schema (Phase 1) — append-only / high-throughput design
CREATE DATABASE IF NOT EXISTS zia;

-- Latest alert state via ReplacingMergeTree (re-insert rows with higher version)
CREATE TABLE IF NOT EXISTS zia.zero_day_alerts
(
    alert_id UUID,
    tenant_id String,
    status LowCardinality(String) DEFAULT 'new',
    severity LowCardinality(String),
    title String DEFAULT '',
    source LowCardinality(String) DEFAULT '',
    verdict LowCardinality(String) DEFAULT '',
    cve_ids Array(String) DEFAULT [],
    iocs Array(String) DEFAULT [],
    fingerprint String DEFAULT '',
    affected_asset_count UInt32 DEFAULT 0,
    investigation_run_id Nullable(UUID),
    raw_payload String DEFAULT '{}',
    created_at DateTime64(3, 'UTC') DEFAULT now64(3),
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3),
    row_version UInt64 DEFAULT toUnixTimestamp64Milli(now64(3))
)
ENGINE = ReplacingMergeTree(row_version)
ORDER BY alert_id
PARTITION BY toYYYYMM(created_at)
SETTINGS index_granularity = 8192;

-- Enrichment artifacts (Mesh, Intel, Vulners, etc.) — immutable append stream
CREATE TABLE IF NOT EXISTS zia.enrichment_evidence
(
    evidence_id UUID,
    alert_id UUID,
    tenant_id String,
    source LowCardinality(String),
    evidence_type LowCardinality(String),
    timestamp DateTime64(3, 'UTC'),
    summary String DEFAULT '',
    payload String DEFAULT '{}',
    confidence Float32 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, alert_id, evidence_id)
SETTINGS index_granularity = 8192;

-- Live agent trace / step logs
CREATE TABLE IF NOT EXISTS zia.agent_events
(
    event_id UUID,
    investigation_run_id UUID,
    alert_id Nullable(UUID),
    tenant_id String,
    event_type LowCardinality(String),
    step_index UInt32 DEFAULT 0,
    timestamp DateTime64(3, 'UTC'),
    message String DEFAULT '',
    metadata String DEFAULT '{}'
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, investigation_run_id, event_id)
SETTINGS index_granularity = 8192;

-- LLM token / cost telemetry
CREATE TABLE IF NOT EXISTS zia.token_usage
(
    usage_id UUID,
    investigation_run_id UUID,
    alert_id Nullable(UUID),
    tenant_id String,
    model LowCardinality(String),
    provider LowCardinality(String) DEFAULT 'anthropic',
    input_tokens UInt32 DEFAULT 0,
    output_tokens UInt32 DEFAULT 0,
    total_tokens UInt32 DEFAULT 0,
    estimated_cost_usd Float64 DEFAULT 0,
    cache_creation_tokens UInt32 DEFAULT 0,
    cache_read_tokens UInt32 DEFAULT 0,
    timestamp DateTime64(3, 'UTC')
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, investigation_run_id, usage_id)
SETTINGS index_granularity = 8192;

-- Local deduplication / correlation graph edges (mirrors Neo4j relationships at ingest)
CREATE TABLE IF NOT EXISTS zia.alert_links
(
    link_id UUID,
    source_alert_id UUID,
    target_alert_id UUID,
    link_type LowCardinality(String),
    confidence Float32 DEFAULT 0,
    reason String DEFAULT '',
    timestamp DateTime64(3, 'UTC')
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (source_alert_id, target_alert_id, link_type, timestamp)
SETTINGS index_granularity = 8192;
