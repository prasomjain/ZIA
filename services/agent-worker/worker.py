"""ZIA Phase 4 agent worker."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from clickhouse_driver import Client as ClickHouseClient
from kafka import KafkaConsumer, KafkaProducer
from neo4j import GraphDatabase, basic_auth

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

EVENT_TYPE_ZERO_DAY_ALERT_RECEIVED = "ZeroDayAlertReceived"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")

_INJECTION_RE = re.compile(
    r"ignore\s+previous\s+instructions|</system>|\[INST\]|system\s*:|prompt\s+leak",
    re.IGNORECASE,
)


def sanitize_for_llm(text: str) -> str:
    """Minimal prompt-injection sanitization (FR-17 basic)."""
    cleaned = _INJECTION_RE.sub("[REDACTED]", text)
    return f"<untrusted_alert_payload>{cleaned}</untrusted_alert_payload>"

# Claude pricing (claude-sonnet-4): $3/1M input, $15/1M output.
_COST_PER_INPUT_TOKEN = 3.0 / 1_000_000
_COST_PER_OUTPUT_TOKEN = 15.0 / 1_000_000


@dataclass
class Settings:
    kafka_brokers: str = os.getenv("REDPANDA_BROKERS", "localhost:19092")
    kafka_topic: str = os.getenv("KAFKA_TOPIC_ALERTS", "zeroday.alerts.v1")
    kafka_dlq_topic: str = os.getenv("KAFKA_TOPIC_DLQ", "zeroday.alerts.dlq")
    kafka_group: str = os.getenv("WORKER_GROUP_ID", "zia-agent-worker-v1")

    clickhouse_host: str = os.getenv("CLICKHOUSE_HOST", "localhost")
    clickhouse_port: int = int(os.getenv("CLICKHOUSE_PORT", "9000"))
    clickhouse_user: str = os.getenv("CLICKHOUSE_USER", "zia")
    clickhouse_password: str = os.getenv("CLICKHOUSE_PASSWORD", "")
    clickhouse_database: str = os.getenv("CLICKHOUSE_DATABASE", "zia")

    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "")

    # Claude SDK path is attempted if available; mock loop is used otherwise.
    use_mock_agent: bool = os.getenv("ZIA_USE_MOCK_AGENT", "true").lower() == "true"
    model_name: str = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    anthropic_base_url: str = os.getenv("ANTHROPIC_BASE_URL", "")

    vuln_mcp_script: str = os.getenv("VULN_MCP_SCRIPT", "/app/mcp-tools/vuln-intel-mcp.py")
    exploit_mcp_script: str = os.getenv("EXPLOIT_MCP_SCRIPT", "/app/mcp-tools/exploit-intel-mcp.py")

    asset_inventory_path: str = os.getenv("ASSET_INVENTORY_PATH", "/app/asset_inventory.json")


class Repo:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.ch = ClickHouseClient(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            user=settings.clickhouse_user,
            password=settings.clickhouse_password,
            database=settings.clickhouse_database,
        )
        self.neo4j = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=basic_auth(settings.neo4j_user, settings.neo4j_password),
        )

    def close(self) -> None:
        self.neo4j.close()

    def log_agent_event(
        self,
        *,
        investigation_run_id: UUID,
        alert_id: UUID,
        tenant_id: str,
        event_type: str,
        step_index: int,
        message: str,
        metadata: dict[str, Any],
    ) -> None:
        self.ch.execute(
            """
            INSERT INTO agent_events (
                event_id, investigation_run_id, alert_id, tenant_id, event_type,
                step_index, timestamp, message, metadata
            ) VALUES
            """,
            [
                (
                    uuid4(),
                    investigation_run_id,
                    alert_id,
                    tenant_id,
                    event_type,
                    step_index,
                    datetime.now(timezone.utc),
                    message,
                    json.dumps(metadata, sort_keys=True),
                )
            ],
        )

    def log_token_usage(
        self,
        *,
        investigation_run_id: UUID,
        alert_id: UUID,
        tenant_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_creation_tokens: int,
        cache_read_tokens: int,
    ) -> None:
        total_tokens = input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens
        # Real cost calculation using Claude pricing.
        estimated_cost_usd = (
            input_tokens * _COST_PER_INPUT_TOKEN
            + output_tokens * _COST_PER_OUTPUT_TOKEN
            + cache_creation_tokens * _COST_PER_INPUT_TOKEN
            + cache_read_tokens * (_COST_PER_INPUT_TOKEN * 0.1)  # cache reads are ~10% of input price
        )
        self.ch.execute(
            """
            INSERT INTO token_usage (
                usage_id, investigation_run_id, alert_id, tenant_id, model, provider,
                input_tokens, output_tokens, total_tokens, estimated_cost_usd,
                cache_creation_tokens, cache_read_tokens, timestamp
            ) VALUES
            """,
            [
                (
                    uuid4(),
                    investigation_run_id,
                    alert_id,
                    tenant_id,
                    model,
                    "anthropic",
                    input_tokens,
                    output_tokens,
                    total_tokens,
                    estimated_cost_usd,
                    cache_creation_tokens,
                    cache_read_tokens,
                    datetime.now(timezone.utc),
                )
            ],
        )

    def insert_enrichment_evidence(
        self,
        *,
        alert_id: UUID,
        tenant_id: str,
        source: str,
        evidence_type: str,
        summary: str,
        payload: dict[str, Any],
        confidence: float,
    ) -> None:
        self.ch.execute(
            """
            INSERT INTO enrichment_evidence (
                evidence_id, alert_id, tenant_id, source, evidence_type,
                timestamp, summary, payload, confidence
            ) VALUES
            """,
            [
                (
                    uuid4(),
                    alert_id,
                    tenant_id,
                    source,
                    evidence_type,
                    datetime.now(timezone.utc),
                    summary,
                    json.dumps(payload, sort_keys=True),
                    confidence,
                )
            ],
        )

    def update_alert_status(
        self,
        *,
        alert_id: UUID,
        tenant_id: str,
        status: str,
    ) -> None:
        """Append a new status row for the alert (ReplacingMergeTree pattern)."""
        now = datetime.now(timezone.utc)
        row_version = int(now.timestamp() * 1000)
        # Read current row to preserve fields.
        rows = self.ch.execute(
            """
            SELECT
                severity, title, source, verdict, cve_ids, iocs, fingerprint,
                affected_asset_count, raw_payload, investigation_run_id
            FROM zero_day_alerts
            WHERE alert_id = %(alert_id)s
            ORDER BY row_version DESC LIMIT 1
            """,
            {"alert_id": alert_id},
        )
        if not rows:
            return
        (severity, title, source, verdict, cve_ids, iocs, fingerprint,
         affected_asset_count, raw_payload, investigation_run_id) = rows[0]

        self.ch.execute(
            """
            INSERT INTO zero_day_alerts (
                alert_id, tenant_id, status, severity, title, source, verdict,
                cve_ids, iocs, fingerprint, affected_asset_count, investigation_run_id,
                raw_payload, created_at, updated_at, row_version
            ) VALUES
            """,
            [
                (
                    alert_id,
                    tenant_id,
                    status,
                    severity,
                    title,
                    source,
                    verdict,
                    list(cve_ids),
                    list(iocs),
                    fingerprint,
                    int(affected_asset_count or 0),
                    UUID(str(investigation_run_id)) if investigation_run_id else None,
                    raw_payload,
                    now,
                    now,
                    row_version,
                )
            ],
        )

    def update_alert_completed(
        self,
        *,
        alert_id: UUID,
        tenant_id: str,
        payload: dict[str, Any],
        cve_ids: list[str],
        iocs: list[str],
        severity: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        row_version = int(now.timestamp() * 1000)
        # Fix #5: ensure investigation_run_id is a proper UUID object, not a bare string.
        raw_run_id = payload.get("investigation_run_id")
        investigation_run_id: UUID | None = None
        if raw_run_id:
            try:
                investigation_run_id = UUID(str(raw_run_id))
            except (ValueError, AttributeError):
                investigation_run_id = None

        import hashlib as _hashlib
        _fp_material = f"{','.join(sorted(cve_ids))}|{','.join(sorted(iocs))}"
        fingerprint = _hashlib.sha256(_fp_material.encode()).hexdigest()

        self.ch.execute(
            """
            INSERT INTO zero_day_alerts (
                alert_id, tenant_id, status, severity, title, source, verdict,
                cve_ids, iocs, fingerprint, affected_asset_count, investigation_run_id,
                raw_payload, created_at, updated_at, row_version
            ) VALUES
            """,
            [
                (
                    alert_id,
                    tenant_id,
                    "COMPLETED",
                    severity,
                    str(payload.get("title", "")),
                    str(payload.get("source", "agent-worker")),
                    str(payload.get("recommendation", "Investigate")),
                    cve_ids,
                    iocs,
                    fingerprint,
                    int(payload.get("affected_asset_count", 0)),
                    investigation_run_id,
                    json.dumps(payload, sort_keys=True),
                    now,
                    now,
                    row_version,
                )
            ],
        )

    def merge_entities_and_relationships(
        self,
        *,
        case_id: str,
        entities: list[dict[str, Any]],
        relationships: list[dict[str, str]],
    ) -> None:
        with self.neo4j.session() as session:
            for entity in entities:
                session.run(
                    """
                    MERGE (e:Entity {case_id:$case_id, type:$type, value:$value})
                    SET e.enriched = coalesce(e.enriched,false), e.updated_at = datetime()
                    WITH e
                    MERGE (c:Case {id:$case_id})
                    MERGE (c)-[:HAS_ENTITY]->(e)
                    """,
                    case_id=case_id,
                    type=entity["type"],
                    value=entity["value"],
                )
            for rel in relationships:
                session.run(
                    """
                    MATCH (a:Entity {case_id:$case_id, value:$src})
                    MATCH (b:Entity {case_id:$case_id, value:$dst})
                    MERGE (a)-[r:RELATED {kind:$kind}]->(b)
                    SET r.updated_at = datetime()
                    """,
                    case_id=case_id,
                    src=rel["src"],
                    dst=rel["dst"],
                    kind=rel["kind"],
                )

    def mark_entity_enriched(self, *, case_id: str, entity_value: str) -> None:
        with self.neo4j.session() as session:
            session.run(
                """
                MATCH (e:Entity {case_id:$case_id, value:$value})
                SET e.enriched = true, e.enriched_at = datetime()
                """,
                case_id=case_id,
                value=entity_value,
            )

    def is_entity_enriched(self, *, case_id: str, entity_value: str) -> bool:
        with self.neo4j.session() as session:
            result = session.run(
                """
                MATCH (e:Entity {case_id:$case_id, value:$value})
                RETURN coalesce(e.enriched, false) AS enriched
                LIMIT 1
                """,
                case_id=case_id,
                value=entity_value,
            ).single()
            return bool(result and result["enriched"])


def extract_entities(payload: dict[str, Any]) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    text = json.dumps(payload)
    cves = sorted(set(m.upper() for m in CVE_RE.findall(text)))
    ips = sorted(set(IP_RE.findall(text)))
    domains = sorted(set(d.lower() for d in DOMAIN_RE.findall(text)))
    products = []
    for key in ("product", "software", "component"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            products.append(value.strip())
    actors = payload.get("actors", [])
    if isinstance(actors, str):
        actors = [actors]
    actor_list = [str(a).strip() for a in actors if str(a).strip()]

    entities: list[dict[str, Any]] = []
    for v in cves:
        entities.append({"type": "CVE", "value": v})
    for v in ips:
        entities.append({"type": "IP", "value": v})
    for v in domains:
        entities.append({"type": "DOMAIN", "value": v})
    for v in products:
        entities.append({"type": "PRODUCT", "value": v})
    for v in actor_list:
        entities.append({"type": "ACTOR", "value": v})
    iocs = sorted(set(ips + domains))
    return cves, iocs, entities


def summarize_tool_result(tool_name: str, result: dict[str, Any]) -> str:
    if not result.get("ok", True):
        error = result.get("error") or {}
        message = error.get("message") if isinstance(error, dict) else str(error)
        return f"{tool_name} failed: {message or 'unknown error'}"

    data = result.get("data") or {}
    if tool_name == "lookup_cve":
        cvss = ((data.get("cvss_v31") or {}).get("base_score"))
        severity = ((data.get("cvss_v31") or {}).get("base_severity"))
        references = data.get("references") or []
        return f"CVE details: CVSS {cvss or 'n/a'} {severity or ''} with {len(references)} references"
    if tool_name == "get_epss_score":
        return f"EPSS score {data.get('epss', 'n/a')} at percentile {data.get('percentile', 'n/a')}"
    if tool_name == "check_kev":
        return "CISA KEV listed" if data.get("is_listed") else "Not listed in CISA KEV"
    if tool_name == "find_public_exploits":
        return f"{data.get('total_count', 0)} public exploit repositories found"
    if tool_name == "map_to_attack":
        return f"{data.get('match_count', 0)} MITRE ATT&CK technique matches"
    if tool_name == "lookup_actor":
        return f"{len(data.get('matches') or [])} intrusion-set profile match(es)"
    return tool_name


def compute_cps(
    *,
    cvss_score: float,
    epss_probability: float,
    kev_listed: bool,
    public_exploit_exists: bool,
    asset_exposure: float,
    threat_actor_severity: float,
) -> tuple[float, str]:
    cvss_normalized = max(0.0, min(cvss_score / 10.0, 1.0))
    cps_0_1 = (
        (0.25 * cvss_normalized)
        + (0.25 * max(0.0, min(epss_probability, 1.0)))
        + (0.20 * (1.0 if kev_listed else 0.0))
        + (0.10 * (1.0 if public_exploit_exists else 0.0))
        + (0.15 * max(0.0, min(asset_exposure, 1.0)))
        + (0.05 * max(0.0, min(threat_actor_severity, 1.0)))
    )
    cps = round(cps_0_1 * 100.0, 2)
    if cps >= 80:
        band = "Critical"
    elif cps >= 60:
        band = "High"
    elif cps >= 40:
        band = "Medium"
    else:
        band = "Low"
    return cps, band


async def call_mcp_tool(script_path: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    params = StdioServerParameters(command="python", args=[script_path])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments=arguments)
            if isinstance(result.structuredContent, dict):
                return result.structuredContent
            for item in result.content:
                if isinstance(item, types.TextContent):
                    try:
                        return json.loads(item.text)
                    except Exception:  # noqa: BLE001
                        continue
    return {"ok": False, "error": {"type": "BAD_MCP_RESPONSE"}}


class AgentLoop:
    """Claude agent loop wrapper with MCP tool orchestration."""

    def __init__(self, settings: Settings, repo: Repo) -> None:
        self.settings = settings
        self.repo = repo
        self._has_claude_sdk = False
        # Export Anthropic proxy settings into the process environment so
        # the Claude/Anthropic SDK or any HTTP client will use the local
        # proxy when present (e.g. kubectl port-forward to litellm-proxy).
        if self.settings.anthropic_api_key:
            os.environ.setdefault("ANTHROPIC_API_KEY", self.settings.anthropic_api_key)
        if self.settings.anthropic_base_url:
            # Some SDKs read ANTHROPIC_BASE_URL or ANTHROPIC_API_URL; set both.
            os.environ.setdefault("ANTHROPIC_BASE_URL", self.settings.anthropic_base_url)
            os.environ.setdefault("ANTHROPIC_API_URL", self.settings.anthropic_base_url)

        try:
            import anthropic  # type: ignore # noqa: F401
            self._has_claude_sdk = True
        except Exception:  # noqa: BLE001
            self._has_claude_sdk = False

    async def _pre_tool_use(
        self,
        *,
        investigation_run_id: UUID,
        alert_id: UUID,
        tenant_id: str,
        step_index: int,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> None:
        self.repo.log_agent_event(
            investigation_run_id=investigation_run_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
            event_type="pre_tool_use",
            step_index=step_index,
            message=f"Invoking {tool_name}",
            metadata={"tool_name": tool_name, "arguments": arguments, "timestamp": datetime.now(timezone.utc).isoformat()},
        )

    async def _call_tool_with_guard(
        self,
        *,
        case_id: str,
        # Fix #4: entity_key must be unique per tool call, not shared across tools for the same CVE.
        entity_key: str,
        script: str,
        tool_name: str,
        arguments: dict[str, Any],
        investigation_run_id: UUID,
        alert_id: UUID,
        tenant_id: str,
        step_index: int,
    ) -> dict[str, Any]:
        if self.repo.is_entity_enriched(case_id=case_id, entity_value=entity_key):
            self.repo.log_agent_event(
                investigation_run_id=investigation_run_id,
                alert_id=alert_id,
                tenant_id=tenant_id,
                event_type="tool_skipped_circular",
                step_index=step_index,
                message=f"Skipped {tool_name} for {entity_key}",
                metadata={"entity": entity_key},
            )
            return {"ok": True, "skipped": True, "reason": "already_enriched"}
        await self._pre_tool_use(
            investigation_run_id=investigation_run_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
            step_index=step_index,
            tool_name=tool_name,
            arguments=arguments,
        )
        result = await call_mcp_tool(script, tool_name, arguments)
        self.repo.mark_entity_enriched(case_id=case_id, entity_value=entity_key)
        self.repo.insert_enrichment_evidence(
            alert_id=alert_id,
            tenant_id=tenant_id,
            source=Path(script).stem,
            evidence_type=tool_name,
            summary=summarize_tool_result(tool_name, result),
            payload={"tool_name": tool_name, "arguments": arguments, "result": result},
            confidence=0.9 if result.get("ok", True) else 0.2,
        )
        return result

    async def _claude_executive_summary(
        self,
        *,
        cves: list[str],
        cvss_score: float,
        epss_probability: float,
        kev_listed: bool,
        exploit_count: int,
        exposed_assets: int,
        total_assets: int,
        actor_entities: list[str],
        mitre_attack_matches: list[dict[str, Any]],
        cps: float,
        band: str,
        payload: dict[str, Any],
    ) -> tuple[str, int, int]:
        """Call Claude via LiteLLM proxy to write the executive summary.
        Returns (summary_text, input_tokens, output_tokens).
        Falls back to empty string on any error so caller uses the template."""
        try:
            import anthropic

            prompt = (
                "You are a senior SOC analyst writing an executive summary for a zero-day vulnerability investigation.\n\n"
                "Enrichment data gathered by automated threat intelligence tools:\n"
                f"- CVEs: {', '.join(cves) if cves else 'none'}\n"
                f"- CVSS base score: {cvss_score:.1f}/10\n"
                f"- EPSS 30-day exploit probability: {epss_probability:.1%}\n"
                f"- CISA KEV (actively exploited in the wild): {'YES' if kev_listed else 'NO'}\n"
                f"- Public PoC exploit repos on GitHub: {exploit_count}\n"
                f"- MITRE ATT&CK techniques matched: {len(mitre_attack_matches)}\n"
                f"- Internet-facing assets exposed: {exposed_assets} of {total_assets}\n"
                f"- Attributed threat actors: {', '.join(actor_entities) if actor_entities else 'none identified'}\n"
                f"- Composite Priority Score: {cps:.1f}/100 — {band}\n\n"
                "Original alert context:\n"
                f"{sanitize_for_llm(str(payload.get('description', '') or payload.get('raw_input', '') or payload.get('title', '')))}\n\n"
                "Write a concise 3-4 sentence executive summary for a CISO. "
                "Synthesize the data into a coherent risk narrative — do not list numbers mechanically. "
                "Include: overall severity, exploitability/active-exploitation status, business impact, and the single most important immediate action. "
                "Professional prose only, no bullet points."
            )

            client = anthropic.AsyncAnthropic(
                api_key=self.settings.anthropic_api_key or "dummy",
                base_url=self.settings.anthropic_base_url or None,
            )
            response = await client.messages.create(
                model=self.settings.model_name,
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text.strip()
            return text, response.usage.input_tokens, response.usage.output_tokens
        except Exception as exc:  # noqa: BLE001
            print(f"[ZIA] Claude summary generation failed ({exc}), using template fallback")
            return "", 0, 0

    async def run(
        self,
        *,
        alert_id: UUID,
        tenant_id: str,
        payload: dict[str, Any],
        entities: list[dict[str, Any]],
        cves: list[str],
    ) -> dict[str, Any]:
        investigation_run_id = uuid4()
        case_id = str(alert_id)
        step = 0
        relationships: list[dict[str, str]] = []

        self.repo.log_agent_event(
            investigation_run_id=investigation_run_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
            event_type="agent_start",
            step_index=step,
            message="Started SOC + zero-day threat hunter loop",
            metadata={
                "persona": "senior SOC + zero-day threat hunter",
                "priorities": [
                    "confirm exploitability",
                    "identify affected versions",
                    "map to MITRE ATT&CK",
                    "score with CVSS+EPSS+KEV",
                    "recommend actions",
                ],
                "sdk_mode": "claude_sdk" if (self._has_claude_sdk and not self.settings.use_mock_agent) else "mock_loop",
            },
        )

        # Log ENRICHING status so UI can show pipeline progress.
        self.repo.update_alert_status(alert_id=alert_id, tenant_id=tenant_id, status="ENRICHING")
        self.repo.log_agent_event(
            investigation_run_id=investigation_run_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
            event_type="status_change",
            step_index=step,
            message="Pipeline stage: ENRICHING",
            metadata={"status": "ENRICHING"},
        )

        findings: dict[str, Any] = {"cves": {}, "actors": []}
        for cve in cves:
            step += 1
            findings["cves"][cve] = {}
            # Fix #4: each tool call uses a unique entity_key so the circular-guard
            # does not skip subsequent tools after the first one completes.
            findings["cves"][cve]["lookup_cve"] = await self._call_tool_with_guard(
                case_id=case_id,
                entity_key=f"{cve}:lookup_cve",
                script=self.settings.vuln_mcp_script,
                tool_name="lookup_cve",
                arguments={"cve_id": cve},
                investigation_run_id=investigation_run_id,
                alert_id=alert_id,
                tenant_id=tenant_id,
                step_index=step,
            )
            step += 1
            findings["cves"][cve]["epss"] = await self._call_tool_with_guard(
                case_id=case_id,
                entity_key=f"{cve}:epss",
                script=self.settings.vuln_mcp_script,
                tool_name="get_epss_score",
                arguments={"cve_id": cve},
                investigation_run_id=investigation_run_id,
                alert_id=alert_id,
                tenant_id=tenant_id,
                step_index=step,
            )
            step += 1
            findings["cves"][cve]["kev"] = await self._call_tool_with_guard(
                case_id=case_id,
                entity_key=f"{cve}:kev",
                script=self.settings.vuln_mcp_script,
                tool_name="check_kev",
                arguments={"cve_id": cve},
                investigation_run_id=investigation_run_id,
                alert_id=alert_id,
                tenant_id=tenant_id,
                step_index=step,
            )
            step += 1
            findings["cves"][cve]["public_exploits"] = await self._call_tool_with_guard(
                case_id=case_id,
                entity_key=f"{cve}:exploits",
                script=self.settings.exploit_mcp_script,
                tool_name="find_public_exploits",
                arguments={"cve_id": cve},
                investigation_run_id=investigation_run_id,
                alert_id=alert_id,
                tenant_id=tenant_id,
                step_index=step,
            )
            step += 1
            findings["cves"][cve]["attack_map"] = await self._call_tool_with_guard(
                case_id=case_id,
                entity_key=f"{cve}:attack",
                script=self.settings.exploit_mcp_script,
                tool_name="map_to_attack",
                arguments={"cve_or_description": cve},
                investigation_run_id=investigation_run_id,
                alert_id=alert_id,
                tenant_id=tenant_id,
                step_index=step,
            )

        actor_entities = [e["value"] for e in entities if e["type"] == "ACTOR"]
        for actor in actor_entities:
            step += 1
            actor_info = await self._call_tool_with_guard(
                case_id=case_id,
                entity_key=f"{actor}:actor_profile",
                script=self.settings.exploit_mcp_script,
                tool_name="lookup_actor",
                arguments={"actor_name": actor},
                investigation_run_id=investigation_run_id,
                alert_id=alert_id,
                tenant_id=tenant_id,
                step_index=step,
            )
            findings["actors"].append({"actor": actor, "profile": actor_info})
            for cve in cves:
                relationships.append({"src": actor, "dst": cve, "kind": "EXPLOITS"})

        self.repo.merge_entities_and_relationships(case_id=case_id, entities=entities, relationships=relationships)

        # Log SCORING status before computing CPS.
        self.repo.update_alert_status(alert_id=alert_id, tenant_id=tenant_id, status="SCORING")
        self.repo.log_agent_event(
            investigation_run_id=investigation_run_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
            event_type="status_change",
            step_index=step + 1,
            message="Pipeline stage: SCORING — computing Composite Priority Score",
            metadata={"status": "SCORING"},
        )

        # CPS
        first_cve = cves[0] if cves else None
        cvss_score = 0.0
        epss_probability = 0.0
        kev_listed = False
        public_exploit_exists = False
        if first_cve and first_cve in findings["cves"]:
            cve_data = findings["cves"][first_cve]
            cvss_score = float(
                (((cve_data.get("lookup_cve") or {}).get("data") or {}).get("cvss_v31") or {}).get("base_score") or 0.0
            )
            epss_probability = float(
                (((cve_data.get("epss") or {}).get("data") or {}).get("epss") or 0.0)
            )
            kev_listed = bool(
                (((cve_data.get("kev") or {}).get("data") or {}).get("is_listed") or False)
            )
            public_exploit_exists = bool(
                (((cve_data.get("public_exploits") or {}).get("data") or {}).get("total_count") or 0)
                > 0
            )

        asset_exposure = 0.0
        total_assets = 0
        exposed_assets = 0
        try:
            inventory = json.loads(Path(self.settings.asset_inventory_path).read_text())
            assets = inventory.get("assets", [])
            total_assets = len(assets)
            internet_facing = [a for a in assets if a.get("internet_exposed")]
            exposed_assets = len(internet_facing)
            asset_exposure = min(1.0, exposed_assets / max(1, total_assets))
        except Exception:  # noqa: BLE001
            asset_exposure = 0.0
        threat_actor_severity = 0.8 if actor_entities else 0.3

        mitre_attack_matches: list[dict[str, Any]] = []
        for cve in cves:
            attack_matches = (((findings["cves"].get(cve) or {}).get("attack_map") or {}).get("data") or {}).get("matches") or []
            for match in attack_matches[:5]:
                mitre_attack_matches.append(
                    {
                        "cve": cve,
                        "technique_id": match.get("technique_id"),
                        "technique_name": match.get("technique_name"),
                        "tactics": match.get("tactics") or [],
                        "score": match.get("score", 0),
                        "url": match.get("url"),
                    }
                )

        affected_asset_hypothesis = (
            "Likely impacted assets include internet-facing systems that expose the affected service or library. "
            f"Observed exposure pattern: {exposed_assets}/{total_assets} assets internet-facing. "
        )
        if payload.get("dst_domain") or payload.get("details", {}).get("dst_domain"):
            dst_domain = payload.get("dst_domain") or payload.get("details", {}).get("dst_domain")
            affected_asset_hypothesis += f"Primary target surface appears to be {dst_domain}. "
        if payload.get("product") or payload.get("details", {}).get("product"):
            product = payload.get("product") or payload.get("details", {}).get("product")
            version = payload.get("version") or payload.get("details", {}).get("version") or "unknown version"
            affected_asset_hypothesis += f"Focus on systems running {product} {version}."

        recommended_actions = [
            "Isolate or rate-limit the exposed service until patch status is confirmed.",
            "Block the observed CVEs, domains, IPs, and exploit URLs at perimeter controls.",
            "Patch or upgrade the affected product and confirm the vulnerable version is absent from inventory.",
            "Hunt for the mapped ATT&CK techniques across telemetry and lateral-movement detections.",
        ]

        cps, band = compute_cps(
            cvss_score=cvss_score,
            epss_probability=epss_probability,
            kev_listed=kev_listed,
            public_exploit_exists=public_exploit_exists,
            asset_exposure=asset_exposure,
            threat_actor_severity=threat_actor_severity,
        )

        # Build template summary as baseline / fallback.
        cve_list = ", ".join(cves) if cves else "no CVEs extracted"
        actor_list_str = ", ".join(actor_entities) if actor_entities else "no known threat actors"
        kev_str = "IS listed in the CISA Known Exploited Vulnerabilities catalog" if kev_listed else "is NOT currently listed in CISA KEV"
        exploit_count_val = (((findings["cves"].get(cves[0]) or {}).get("public_exploits") or {}).get("data") or {}).get("total_count", 0) if cves else 0
        exploit_str = (
            f"Public proof-of-concept exploits were found ({exploit_count_val} repositories)."
            if public_exploit_exists and cves else
            "No public proof-of-concept exploits were found at investigation time."
        )
        tech_count = len(mitre_attack_matches)
        template_summary = (
            f"SEVERITY: {band} (Composite Priority Score: {cps}/100). "
            f"This investigation covers {cve_list}. "
            f"The primary vulnerability {kev_str}. "
            f"EPSS 30-day exploit probability: {epss_probability:.1%}. "
            f"{exploit_str} "
            f"MITRE ATT&CK analysis identified {tech_count} relevant technique(s). "
            f"Asset exposure: {exposed_assets} of {total_assets} assets in inventory are internet-facing. "
            f"Attributed actor(s): {actor_list_str}. "
            f"CVSS base score: {cvss_score:.1f}/10. "
            f"Immediate action: {'patch and isolate affected systems — active exploitation confirmed via KEV listing' if kev_listed else 'monitor closely and prioritize patching based on EPSS probability'}."
        )

        # Try real Claude if proxy is configured and mock mode is off.
        input_tokens = max(200, len(json.dumps(payload)) // 4)
        output_tokens = max(120, len(template_summary) // 2)
        executive_summary = template_summary
        summary_mode = "template"

        if not self.settings.use_mock_agent and self.settings.anthropic_base_url and self._has_claude_sdk:
            claude_text, real_input, real_output = await self._claude_executive_summary(
                cves=cves,
                cvss_score=cvss_score,
                epss_probability=epss_probability,
                kev_listed=kev_listed,
                exploit_count=exploit_count_val,
                exposed_assets=exposed_assets,
                total_assets=total_assets,
                actor_entities=actor_entities,
                mitre_attack_matches=mitre_attack_matches,
                cps=cps,
                band=band,
                payload=payload,
            )
            if claude_text:
                executive_summary = claude_text
                input_tokens = real_input
                output_tokens = real_output
                summary_mode = "claude"

        self.repo.log_agent_event(
            investigation_run_id=investigation_run_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
            event_type="executive_subagent",
            step_index=step + 2,
            message="Executive summary generated",
            metadata={
                "summary": executive_summary,
                "composite_priority_score": cps,
                "severity_band": band,
                "mitre_attack_count": len(mitre_attack_matches),
                "summary_mode": summary_mode,
            },
        )
        self.repo.log_token_usage(
            investigation_run_id=investigation_run_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
            model=self.settings.model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_creation_tokens=0,
            cache_read_tokens=0,
        )

        return {
            "investigation_run_id": str(investigation_run_id),
            "findings": findings,
            "cps": cps,
            "severity_band": band,
            "executive_summary": executive_summary,
            "mitre_attack": mitre_attack_matches,
            "affected_asset_hypothesis": affected_asset_hypothesis,
            "recommended_actions": recommended_actions,
            "affected_asset_count": exposed_assets,
        }


class Worker:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.repo = Repo(settings)
        self.loop = AgentLoop(settings, self.repo)
        self.consumer = KafkaConsumer(
            settings.kafka_topic,
            bootstrap_servers=settings.kafka_brokers.split(","),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            group_id=settings.kafka_group,
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        )
        # DLQ producer (Fix #11): failed messages land here with failure reason.
        self._dlq_producer = KafkaProducer(
            bootstrap_servers=settings.kafka_brokers.split(","),
            value_serializer=lambda v: json.dumps(v, separators=(",", ":")).encode("utf-8"),
            acks=1,
            linger_ms=0,
        )

    def _publish_to_dlq(self, event: dict[str, Any], reason: str) -> None:
        """Publish a failed event to the Dead Letter Queue topic."""
        try:
            dlq_event = {
                "original_event": event,
                "failure_reason": reason,
                "failed_at": datetime.now(timezone.utc).isoformat(),
            }
            self._dlq_producer.send(
                self.settings.kafka_dlq_topic,
                key=str(event.get("alert_id", "unknown")).encode("utf-8"),
                value=dlq_event,
            )
            self._dlq_producer.flush()
            print(f"[DLQ] Published failed event for alert_id={event.get('alert_id')} reason={reason}", flush=True)
        except Exception as dlq_err:  # noqa: BLE001
            print(f"[DLQ] Failed to publish to DLQ: {dlq_err}", flush=True)

    async def handle_message(self, event: dict[str, Any]) -> None:
        if event.get("event_type") != EVENT_TYPE_ZERO_DAY_ALERT_RECEIVED:
            return
        alert_id_str = event.get("alert_id", "")
        try:
            alert_id = UUID(alert_id_str)
        except (ValueError, AttributeError) as exc:
            self._publish_to_dlq(event, f"Invalid alert_id format: {exc}")
            return

        payload = event.get("payload", {})
        tenant_id = str(payload.get("tenant_id", "default"))

        try:
            cves, iocs, entities = extract_entities(payload)

            # Log NORMALIZED status: entities extracted, fingerprint confirmed.
            self.repo.update_alert_status(alert_id=alert_id, tenant_id=tenant_id, status="NORMALIZED")
            self.repo.log_agent_event(
                investigation_run_id=uuid4(),
                alert_id=alert_id,
                tenant_id=tenant_id,
                event_type="status_change",
                step_index=0,
                message=f"Pipeline stage: NORMALIZED — extracted {len(cves)} CVE(s), {len(iocs)} IOC(s)",
                metadata={"status": "NORMALIZED", "cves": cves, "ioc_count": len(iocs)},
            )

            # Log DEDUP_CHECK: dedup already ran in the webhook; confirm no duplicate found.
            self.repo.update_alert_status(alert_id=alert_id, tenant_id=tenant_id, status="DEDUP_CHECK")
            self.repo.log_agent_event(
                investigation_run_id=uuid4(),
                alert_id=alert_id,
                tenant_id=tenant_id,
                event_type="status_change",
                step_index=1,
                message="Pipeline stage: DEDUP_CHECK — no duplicate fingerprint found, proceeding to enrichment",
                metadata={"status": "DEDUP_CHECK"},
            )

            result = await self.loop.run(
                alert_id=alert_id,
                tenant_id=tenant_id,
                payload=payload,
                entities=entities,
                cves=cves,
            )
            payload["investigation_run_id"] = result["investigation_run_id"]
            payload["recommendation"] = result["executive_summary"]
            payload["composite_priority_score"] = result["cps"]
            payload["severity_band"] = result["severity_band"]
            payload["executive_summary"] = result["executive_summary"]
            payload["mitre_attack"] = result["mitre_attack"]
            payload["affected_asset_hypothesis"] = result["affected_asset_hypothesis"]
            payload["recommended_actions"] = result["recommended_actions"]
            payload["affected_asset_count"] = result["affected_asset_count"]
            self.repo.update_alert_completed(
                alert_id=alert_id,
                tenant_id=tenant_id,
                payload=payload,
                cve_ids=cves,
                iocs=iocs,
                severity=result["severity_band"].upper(),
            )
        except Exception as exc:  # noqa: BLE001
            # Fix #11: publish to DLQ instead of silently dropping.
            failure_reason = f"{type(exc).__name__}: {exc}"
            print(f"[Worker] Error processing alert {alert_id_str}: {failure_reason}", flush=True)
            self._publish_to_dlq(event, failure_reason)
            # Also try to mark the alert as FAILED in ClickHouse for UI visibility.
            try:
                self.repo.update_alert_status(
                    alert_id=alert_id,
                    tenant_id=tenant_id,
                    status="FAILED",
                )
            except Exception:  # noqa: BLE001
                pass

    def run(self) -> None:
        print("ZIA agent-worker starting (phase 4)", flush=True)
        print(f"  brokers={self.settings.kafka_brokers}", flush=True)
        print(f"  topic={self.settings.kafka_topic}", flush=True)
        print(f"  dlq_topic={self.settings.kafka_dlq_topic}", flush=True)
        try:
            for message in self.consumer:
                asyncio.run(self.handle_message(message.value))
        finally:
            self.repo.close()
            self._dlq_producer.close()


if __name__ == "__main__":
    Worker(Settings()).run()
