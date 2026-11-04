"""FastAPI application entry-point with CORS, lifespan, and FastMCP SSE mount."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.firebase_client import firebase_manager
from app.mcp_tools import mcp

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("warden")


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("🛡️  Your Warden backend starting …")
    firebase_manager.initialize()
    logger.info("✅  Firebase Admin SDK initialised")
    yield
    logger.info("🛡️  Your Warden backend shutting down …")


app = FastAPI(
    title="Your Warden – AI Application Firewall",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Mount FastMCP over SSE at /mcp ───────────────────────────────────────────
sse_app = mcp.sse_app()
app.mount("/mcp", sse_app)

# ── Health probe ─────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "your-warden"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
