import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from clickhouse_driver import Client

from app.config import Settings


class ClickHouseRepository:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = Client(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            user=settings.clickhouse_user,
            password=settings.clickhouse_password,
            database=settings.clickhouse_database,
        )

    def find_canonical_alert_by_fingerprint(self, fingerprint: str) -> UUID | None:
        rows = self._client.execute(
            """
            SELECT alert_id
            FROM zero_day_alerts FINAL
            WHERE fingerprint = %(fingerprint)s
              AND status != 'DUPLICATE'
            ORDER BY created_at ASC
            LIMIT 1
            """,
            {"fingerprint": fingerprint},
        )
        if not rows:
            return None
        return rows[0][0]

    def insert_alert(
        self,
        *,
        alert_id: UUID,
        tenant_id: str,
        status: str,
        cve_ids: list[str],
        iocs: list[str],
        fingerprint: str,
        raw_payload: str,
        severity: str = "",
        title: str = "",
        source: str = "",
    ) -> None:
        now = datetime.now(timezone.utc)
        row_version = int(now.timestamp() * 1000)
        self._client.execute(
            """
            INSERT INTO zero_day_alerts (
                alert_id, tenant_id, status, severity, title, source,
                cve_ids, iocs, fingerprint, raw_payload,
                created_at, updated_at, row_version
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
                    cve_ids,
                    iocs,
                    fingerprint,
                    raw_payload,
                    now,
                    now,
                    row_version,
                )
            ],
        )

    def insert_duplicate_link(
        self,
        *,
        new_alert_id: UUID,
        canonical_alert_id: UUID,
        fingerprint: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        self._client.execute(
            """
            INSERT INTO alert_links (
                link_id, source_alert_id, target_alert_id,
                link_type, confidence, reason, timestamp
            ) VALUES
            """,
            [
                (
                    uuid4(),
                    new_alert_id,
                    canonical_alert_id,
                    "DUPLICATE",
                    1.0,
                    f"Matching fingerprint {fingerprint}",
                    now,
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
        self._client.execute(
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

    def get_alert_status(self, alert_id: UUID) -> str | None:
        rows = self._client.execute(
            """
            SELECT status
            FROM zero_day_alerts
            WHERE alert_id = %(alert_id)s
            ORDER BY row_version DESC
            LIMIT 1
            """,
            {"alert_id": alert_id},
        )
        if not rows:
            return None
        return rows[0][0]

    def get_latest_alert_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        rows = self._client.execute(
            """
            SELECT alert_id, status, fingerprint
            FROM zero_day_alerts
            WHERE fingerprint = %(fingerprint)s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            {"fingerprint": fingerprint},
        )
        if not rows:
            return None
        return {"alert_id": rows[0][0], "status": rows[0][1], "fingerprint": rows[0][2]}

    def get_case_detail(self, alert_id: UUID) -> dict[str, Any] | None:
        alert_rows = self._client.execute(
            """
            SELECT
                alert_id, tenant_id, status, severity, title, source, verdict,
                cve_ids, iocs, fingerprint, affected_asset_count,
                investigation_run_id, raw_payload, created_at, updated_at
            FROM zero_day_alerts
            WHERE alert_id = %(alert_id)s
            ORDER BY row_version DESC
            LIMIT 1
            """,
            {"alert_id": alert_id},
        )
        if not alert_rows:
            return None

        (
            row_alert_id,
            tenant_id,
            status,
            severity,
            title,
            source,
            verdict,
            cve_ids,
            iocs,
            fingerprint,
            affected_asset_count,
            investigation_run_id,
            raw_payload,
            created_at,
            updated_at,
        ) = alert_rows[0]

        def _decode_payload(value: str | dict[str, Any] | None) -> dict[str, Any]:
            if isinstance(value, dict):
                return value
            if not isinstance(value, str) or not value.strip():
                return {}
            try:
                decoded = json.loads(value)
            except Exception:  # noqa: BLE001
                return {"raw_payload": value}
            if isinstance(decoded, dict) and set(decoded.keys()) == {"raw_payload"}:
                nested = decoded.get("raw_payload")
                if isinstance(nested, str) and nested.strip():
                    try:
                        nested_decoded = json.loads(nested)
                        if isinstance(nested_decoded, dict):
                            return nested_decoded
                    except Exception:  # noqa: BLE001
                        pass
            return decoded if isinstance(decoded, dict) else {"raw_payload": value}

        payload = _decode_payload(raw_payload)

        duplicate_rows = self._client.execute(
            """
            SELECT target_alert_id, link_type, confidence, reason, timestamp
            FROM alert_links
            WHERE source_alert_id = %(alert_id)s
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            {"alert_id": alert_id},
        )
        duplicate_link = None
        if duplicate_rows:
            target_alert_id, link_type, confidence, reason, dup_timestamp = duplicate_rows[0]
            duplicate_link = {
                "target_alert_id": str(target_alert_id) if target_alert_id else None,
                "link_type": link_type,
                "confidence": float(confidence),
                "reason": reason,
                "timestamp": dup_timestamp.isoformat() if isinstance(dup_timestamp, datetime) else str(dup_timestamp),
            }

        evidence_rows = self._client.execute(
            """
            SELECT evidence_id, source, evidence_type, timestamp, summary, payload, confidence
            FROM enrichment_evidence
            WHERE alert_id = %(alert_id)s
            ORDER BY timestamp ASC, evidence_id ASC
            LIMIT 300
            """,
            {"alert_id": alert_id},
        )
        evidence: list[dict[str, Any]] = []
        for evidence_id, source_name, evidence_type, timestamp, summary, evidence_payload, confidence in evidence_rows:
            parsed_payload: dict[str, Any] = {}
            if isinstance(evidence_payload, str) and evidence_payload:
                try:
                    parsed_payload = json.loads(evidence_payload)
                except Exception:  # noqa: BLE001
                    parsed_payload = {"raw_payload": evidence_payload}
            evidence.append(
                {
                    "evidence_id": evidence_id,
                    "source": source_name,
                    "evidence_type": evidence_type,
                    "timestamp": timestamp,
                    "summary": summary,
                    "payload": parsed_payload,
                    "confidence": confidence,
                }
            )

        token_rows = self._client.execute(
            """
            SELECT
                sum(input_tokens), sum(output_tokens), sum(total_tokens),
                sum(estimated_cost_usd), sum(cache_creation_tokens), sum(cache_read_tokens)
            FROM token_usage
            WHERE alert_id = %(alert_id)s
            """,
            {"alert_id": alert_id},
        )
        token_usage = {
            "input_tokens": int(token_rows[0][0] or 0),
            "output_tokens": int(token_rows[0][1] or 0),
            "total_tokens": int(token_rows[0][2] or 0),
            "estimated_cost_usd": float(token_rows[0][3] or 0.0),
            "cache_creation_tokens": int(token_rows[0][4] or 0),
            "cache_read_tokens": int(token_rows[0][5] or 0),
        }

        timeline_rows = self._client.execute(
            """
            SELECT event_id, investigation_run_id, event_type, step_index, timestamp, message, metadata
            FROM agent_events
            WHERE alert_id = %(alert_id)s
            ORDER BY timestamp ASC, event_id ASC
            LIMIT 300
            """,
            {"alert_id": alert_id},
        )
        timeline: list[dict[str, Any]] = []
        for event_id, run_id, event_type, step_index, timestamp, message, metadata in timeline_rows:
            parsed_metadata: dict[str, Any] = {}
            if isinstance(metadata, str) and metadata:
                try:
                    parsed_metadata = json.loads(metadata)
                except Exception:  # noqa: BLE001
                    parsed_metadata = {"raw_metadata": metadata}
            timeline.append(
                {
                    "event_id": event_id,
                    "investigation_run_id": run_id,
                    "event_type": event_type,
                    "step_index": int(step_index),
                    "timestamp": timestamp,
                    "message": message,
                    "metadata": parsed_metadata,
                }
            )

        return {
            "alert": {
                "alert_id": str(row_alert_id) if row_alert_id else None,
                "tenant_id": tenant_id,
                "status": status,
                "severity": severity,
                "title": title,
                "source": source,
                "verdict": verdict,
                "cve_ids": list(cve_ids),
                "iocs": list(iocs),
                "fingerprint": fingerprint,
                "affected_asset_count": int(affected_asset_count or 0),
                "investigation_run_id": str(investigation_run_id) if investigation_run_id else None,
                "created_at": created_at.isoformat() if isinstance(created_at, datetime) else str(created_at),
                "updated_at": updated_at.isoformat() if isinstance(updated_at, datetime) else str(updated_at),
            },
            "payload": payload,
            "duplicate_link": duplicate_link,
            "evidence": evidence,
            "token_usage": token_usage,
            "timeline": timeline,
        }

    def list_alerts(
        self,
        *,
        limit: int = 100,
        status_filter: str | None = None,
        severity_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return a summary list of alerts for the dashboard, newest first."""
        conditions = []
        params: dict[str, Any] = {"limit": limit}
        if status_filter:
            conditions.append("status = %(status_filter)s")
            params["status_filter"] = status_filter
        if severity_filter:
            conditions.append("severity = %(severity_filter)s")
            params["severity_filter"] = severity_filter

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        rows = self._client.execute(
            f"""
            SELECT
                alert_id, tenant_id, status, severity, title, source,
                cve_ids, fingerprint, affected_asset_count,
                raw_payload, created_at, updated_at
            FROM zero_day_alerts
            FINAL
            {where_clause}
            ORDER BY created_at DESC
            LIMIT %(limit)s
            """,
            params,
        )

        results: list[dict[str, Any]] = []
        for row in rows:
            (
                alert_id, tenant_id, status, severity, title, source,
                cve_ids, fingerprint, affected_asset_count,
                raw_payload, created_at, updated_at,
            ) = row

            # Extract composite_priority_score from raw_payload if available
            cps: float | None = None
            severity_band: str | None = None
            try:
                rp = json.loads(raw_payload) if isinstance(raw_payload, str) else (raw_payload or {})
                cps = rp.get("composite_priority_score")
                severity_band = rp.get("severity_band")
            except Exception:  # noqa: BLE001
                pass

            results.append({
                "alert_id": str(alert_id) if alert_id else None,
                "tenant_id": tenant_id,
                "status": status,
                "severity": severity,
                "severity_band": severity_band or severity,
                "title": title,
                "source": source,
                "top_cve": list(cve_ids)[0] if cve_ids else None,
                "fingerprint": fingerprint,
                "affected_asset_count": int(affected_asset_count or 0),
                "composite_priority_score": float(cps) if cps is not None else None,
                "created_at": created_at.isoformat() if isinstance(created_at, datetime) else str(created_at),
                "updated_at": updated_at.isoformat() if isinstance(updated_at, datetime) else str(updated_at),
            })
        return results
