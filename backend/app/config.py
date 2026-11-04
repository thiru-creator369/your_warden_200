"""Application configuration via Pydantic BaseSettings."""

from __future__ import annotations

import json
import os
from typing import List, Optional

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Central configuration loaded from environment variables / .env."""

    # --- Server ---
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # --- CORS ---
    CORS_ORIGINS: List[str] = [
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://*.web.app",
        "https://*.firebaseapp.com",
    ]

    # --- Firebase ---
    FIREBASE_SERVICE_ACCOUNT_PATH: str = Field(
        default="serviceAccountKey.json",
        description="Path to the Firebase service-account JSON file.",
    )
    FIREBASE_SERVICE_ACCOUNT_JSON: Optional[str] = Field(
        default=None,
        description="Base64 or raw JSON string of the service-account credentials. Takes priority over the file path.",
    )
    FIREBASE_DATABASE_URL: str = "https://your-warden-default-rtdb.firebaseio.com"

    # --- Risk Thresholds ---
    RISK_LOW_MAX: float = 0.25
    RISK_MEDIUM_MAX: float = 0.65

    # --- Evaluator AI ---
    EVALUATOR_MODEL: str = "gemini-2.0-flash"
    EVALUATOR_TIMEOUT: int = 30

    # --- Quarantine ---
    QUARANTINE_POLL_INTERVAL: float = 0.5
    QUARANTINE_TIMEOUT: int = 120

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
