import asyncio
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from app.auth import verify_webhook_secret
from app.clickhouse_repo import ClickHouseRepository
from app.config import get_settings
from app.kafka_events import AlertEventPublisher
from app.normalization import normalize_payload, payload_to_json

router = APIRouter(prefix="/api/v1/webhook", tags=["webhook"])

_repo: ClickHouseRepository | None = None
_publisher: AlertEventPublisher | None = None


def get_repo() -> ClickHouseRepository:
    global _repo
    if _repo is None:
        _repo = ClickHouseRepository(get_settings())
    return _repo


def get_publisher() -> AlertEventPublisher:
    global _publisher
    if _publisher is None:
        _publisher = AlertEventPublisher(get_settings())
    return _publisher


def _tenant_id_from_payload(payload: dict[str, Any]) -> str:
    settings = get_settings()
    for key in ("tenant_id", "tenantId", "tenant"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return settings.default_tenant_id


def _metadata_from_payload(payload: dict[str, Any]) -> tuple[str, str, str]:
    severity = str(payload.get("severity") or payload.get("Severity") or "")
    title = str(payload.get("title") or payload.get("Title") or "")
    source = str(payload.get("source") or payload.get("Source") or "webhook")
    return severity, title, source


@router.post(
    "/zeroday",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_webhook_secret)],
)
async def ingest_zeroday_webhook(request: Request) -> JSONResponse:
    payload: dict[str, Any] = await request.json()
    repo = get_repo()

    cve_ids, iocs, fingerprint = normalize_payload(payload)
    tenant_id = _tenant_id_from_payload(payload)
    severity, title, source = _metadata_from_payload(payload)
    raw_json = payload_to_json(payload)

    # Run all blocking ClickHouse calls in a thread so the event loop stays free.
    canonical_id = await asyncio.to_thread(
        repo.find_canonical_alert_by_fingerprint, fingerprint
    )
    new_alert_id = uuid4()

    if canonical_id is not None:
        await asyncio.to_thread(
            repo.insert_alert,
            alert_id=new_alert_id,
            tenant_id=tenant_id,
            status="DUPLICATE",
            cve_ids=cve_ids,
            iocs=iocs,
            fingerprint=fingerprint,
            raw_payload=raw_json,
            severity=severity,
            title=title,
            source=source,
        )
        await asyncio.to_thread(
            repo.insert_duplicate_link,
            new_alert_id=new_alert_id,
            canonical_alert_id=canonical_id,
            fingerprint=fingerprint,
        )
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "alert_id": str(new_alert_id),
                "status": "DUPLICATE",
                "fingerprint": fingerprint,
                "canonical_alert_id": str(canonical_id),
                "duplicate": True,
            },
        )

    await asyncio.to_thread(
        repo.insert_alert,
        alert_id=new_alert_id,
        tenant_id=tenant_id,
        status="RECEIVED",
        cve_ids=cve_ids,
        iocs=iocs,
        fingerprint=fingerprint,
        raw_payload=raw_json,
        severity=severity,
        title=title,
        source=source,
    )

    # Async publish — runs blocking Kafka send in a thread pool.
    await get_publisher().publish_zero_day_alert_received(new_alert_id, payload)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "alert_id": str(new_alert_id),
            "status": "RECEIVED",
            "fingerprint": fingerprint,
            "duplicate": False,
        },
    )
