from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from clickhouse_driver import Client as ClickHouseClient
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.config import get_settings
from app.clickhouse_repo import ClickHouseRepository

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

# Terminal statuses — no more agent events will arrive after these.
_TERMINAL_STATUSES = frozenset({"COMPLETED", "DUPLICATE", "FAILED"})

# Singleton repo — reuses one ClickHouse TCP connection instead of opening a
# new one on every request (which is a blocking operation that freezes the loop).
_repo_instance: ClickHouseRepository | None = None


def _repo() -> ClickHouseRepository:
    global _repo_instance
    if _repo_instance is None:
        _repo_instance = ClickHouseRepository(get_settings())
    return _repo_instance


def _new_clickhouse_client() -> ClickHouseClient:
    settings = get_settings()
    return ClickHouseClient(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        user=settings.clickhouse_user,
        password=settings.clickhouse_password,
        database=settings.clickhouse_database,
    )


@router.get("")
async def list_alerts(
    status: Optional[str] = Query(default=None, description="Filter by status"),
    severity: Optional[str] = Query(default=None, description="Filter by severity band"),
    limit: int = Query(default=100, le=500, description="Max rows to return"),
) -> list:
    """Return a summary list of all alerts for the dashboard, newest first."""
    # Run the blocking ClickHouse query in a thread so the event loop stays free.
    return await asyncio.to_thread(
        _repo().list_alerts,
        limit=limit,
        status_filter=status,
        severity_filter=severity,
    )


@router.get("/{alert_id}")
async def get_alert_detail(alert_id: UUID) -> dict:
    detail = await asyncio.to_thread(_repo().get_case_detail, alert_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return detail


@router.get("/{alert_id}/stream")
async def stream_alert_events(alert_id: UUID) -> StreamingResponse:
    async def event_generator():
        # Each SSE connection gets its own ClickHouse client so queries
        # don't share a connection with concurrent requests.
        client = await asyncio.to_thread(_new_clickhouse_client)
        last_ts = datetime(1970, 1, 1, tzinfo=timezone.utc)
        last_event_id = UUID("00000000-0000-0000-0000-000000000000")
        idle_cycles = 0
        _MAX_IDLE_CYCLES = 300  # ~5 minutes of idle before giving up

        def _query_events():
            return client.execute(
                """
                SELECT
                    event_id, investigation_run_id, alert_id, tenant_id,
                    event_type, step_index, timestamp, message, metadata
                FROM agent_events
                WHERE alert_id = %(alert_id)s
                  AND (
                    timestamp > %(last_ts)s
                    OR (timestamp = %(last_ts)s AND event_id > %(last_event_id)s)
                  )
                ORDER BY timestamp ASC, event_id ASC
                LIMIT 200
                """,
                {
                    "alert_id": alert_id,
                    "last_ts": last_ts,
                    "last_event_id": last_event_id,
                },
            )

        def _query_status():
            rows = client.execute(
                """
                SELECT status FROM zero_day_alerts
                WHERE alert_id = %(alert_id)s
                ORDER BY row_version DESC LIMIT 1
                """,
                {"alert_id": alert_id},
            )
            return rows[0][0] if rows else None

        try:
            while True:
                rows = await asyncio.to_thread(_query_events)

                if not rows:
                    idle_cycles += 1
                    current_status = await asyncio.to_thread(_query_status)
                    if current_status in _TERMINAL_STATUSES:
                        yield f"event: done\ndata: {json.dumps({'status': current_status})}\n\n"
                        return
                    if idle_cycles >= _MAX_IDLE_CYCLES:
                        yield "event: done\ndata: {\"status\": \"TIMEOUT\"}\n\n"
                        return
                    yield ": keep-alive\n\n"
                    await asyncio.sleep(1.0)
                    continue

                idle_cycles = 0
                for row in rows:
                    (
                        event_id, investigation_run_id, row_alert_id, tenant_id,
                        event_type, step_index, timestamp, message, metadata,
                    ) = row
                    last_ts = timestamp
                    last_event_id = event_id

                    parsed_meta: dict = {}
                    if isinstance(metadata, str) and metadata:
                        try:
                            parsed_meta = json.loads(metadata)
                        except Exception:  # noqa: BLE001
                            parsed_meta = {"raw_metadata": metadata}

                    payload = {
                        "event_id": str(event_id),
                        "investigation_run_id": str(investigation_run_id),
                        "alert_id": str(row_alert_id) if row_alert_id else None,
                        "tenant_id": tenant_id,
                        "event_type": event_type,
                        "step_index": int(step_index),
                        "timestamp": (
                            timestamp.isoformat()
                            if isinstance(timestamp, datetime)
                            else str(timestamp)
                        ),
                        "message": message,
                        "metadata": parsed_meta,
                    }
                    yield f"id: {payload['event_id']}\n"
                    yield "event: agent_event\n"
                    yield f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"
        finally:
            await asyncio.to_thread(client.disconnect)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
