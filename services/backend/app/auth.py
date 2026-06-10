from fastapi import Header, HTTPException, status

from app.config import get_settings


async def verify_webhook_secret(
    x_webhook_secret: str | None = Header(default=None, alias="x-Webhook-Secret"),
) -> None:
    expected = get_settings().webhook_secret
    # If no secret is configured in environment, reject all requests — no implicit bypass.
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Webhook secret not configured on server",
        )
    if not x_webhook_secret or x_webhook_secret != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing webhook secret",
        )
