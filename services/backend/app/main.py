import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings
from app.routers import alerts, webhook


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Eagerly initialise the Kafka publisher in a thread so the first webhook
    # request doesn't pay the blocking KafkaProducer.__init__ connection cost.
    await asyncio.to_thread(webhook.get_publisher)
    yield
    publisher = webhook._publisher
    if publisher is not None:
        publisher.close()


app = FastAPI(
    title="ZIA Backend",
    version="0.4.0-phase5",
    lifespan=lifespan,
)
app.include_router(webhook.router)
app.include_router(alerts.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "zia-backend", "phase": 2}
