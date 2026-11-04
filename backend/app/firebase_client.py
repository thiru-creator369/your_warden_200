"""Async Firebase Realtime Database manager using firebase-admin SDK."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from typing import Any, Dict, Optional

import firebase_admin
from firebase_admin import credentials, db
import httpx

from app.config import settings

logger = logging.getLogger("warden.firebase")


class FirebaseManager:
    """Wraps firebase-admin with async helpers for RTDB operations, with local fallback."""

    _app: Optional[firebase_admin.App] = None
    _local_cache: Dict[str, Dict[str, Any]] = {}

    def initialize(self) -> None:
        """Initialize the Firebase Admin SDK (idempotent)."""
        if self._app is not None:
            return

        try:
            cred = self._load_credentials()
            self._app = firebase_admin.initialize_app(
                cred,
                {"databaseURL": settings.FIREBASE_DATABASE_URL},
            )
            logger.info("Firebase Admin SDK initialised (project: %s)", self._app.project_id)
        except Exception as exc:
            logger.warning(
                "Firebase Admin SDK not initialized (%s). Running in local in-memory cache mode. "
                "Download serviceAccountKey.json from Firebase Console to enable live cloud sync.",
                exc,
            )

    # ── Credential helpers ───────────────────────────────────────────────
    def _load_credentials(self) -> credentials.Certificate:
        """Load credentials from env-var JSON string or file on disk."""
        env_json = settings.FIREBASE_SERVICE_ACCOUNT_JSON
        if env_json:
            try:
                info = json.loads(env_json)
            except json.JSONDecodeError:
                info = json.loads(base64.b64decode(env_json))
            return credentials.Certificate(info)

        path = settings.FIREBASE_SERVICE_ACCOUNT_PATH
        if not os.path.isabs(path):
            path = os.path.join(os.path.dirname(os.path.dirname(__file__)), path)
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Firebase service-account key not found at '{path}'. "
                "Download it from the Firebase Console → Project Settings → Service Accounts."
            )
        return credentials.Certificate(path)

    # ── Async RTDB helpers ───────────────────────────────────────────────
    async def async_push_incident(self, incident_id: str, data: Dict[str, Any]) -> None:
        """Write an incident record to /incidents/{incident_id}."""
        self._local_cache[incident_id] = data
        if self._app is not None:
            ref = db.reference(f"/incidents/{incident_id}")
            await asyncio.to_thread(ref.set, data)
            logger.info("Incident %s pushed to RTDB via Admin SDK", incident_id)
        else:
            # Fallback to direct REST API
            try:
                url = f"{settings.FIREBASE_DATABASE_URL.rstrip('/')}/incidents/{incident_id}.json"
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.put(url, json=data)
                    resp.raise_for_status()
                logger.info("Incident %s pushed to RTDB via REST API", incident_id)
            except Exception as exc:
                logger.warning("Failed to push incident %s via REST API: %s", incident_id, exc)

    async def async_update_incident_status(
        self,
        incident_id: str,
        status: str,
        resolved_by: str,
    ) -> None:
        """Update the resolution status of an incident."""
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if incident_id in self._local_cache:
            self._local_cache[incident_id]["status"] = status
            self._local_cache[incident_id]["resolved_by"] = resolved_by
            self._local_cache[incident_id]["resolved_at"] = now_iso

        if self._app is not None:
            ref = db.reference(f"/incidents/{incident_id}")
            await asyncio.to_thread(
                ref.update,
                {
                    "status": status,
                    "resolved_by": resolved_by,
                    "resolved_at": {".sv": "timestamp"},
                },
            )
            logger.info("Incident %s resolved → %s (via %s in RTDB Admin)", incident_id, status, resolved_by)
        else:
            try:
                url = f"{settings.FIREBASE_DATABASE_URL.rstrip('/')}/incidents/{incident_id}.json"
                update_payload = {
                    "status": status,
                    "resolved_by": resolved_by,
                    "resolved_at": now_iso,
                }
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.patch(url, json=update_payload)
                    resp.raise_for_status()
                logger.info("Incident %s resolved → %s (via %s in RTDB REST)", incident_id, status, resolved_by)
            except Exception as exc:
                logger.warning("Failed to update incident %s via REST API: %s", incident_id, exc)

    async def async_get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Read a single incident from RTDB or local fallback."""
        if self._app is not None:
            ref = db.reference(f"/incidents/{incident_id}")
            remote = await asyncio.to_thread(ref.get)
            if remote:
                return remote
        else:
            try:
                url = f"{settings.FIREBASE_DATABASE_URL.rstrip('/')}/incidents/{incident_id}.json"
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200 and resp.json():
                        return resp.json()
            except Exception as exc:
                logger.warning("Failed to fetch incident %s via REST API: %s", incident_id, exc)
        return self._local_cache.get(incident_id)

    async def async_poll_for_resolution(
        self,
        incident_id: str,
        timeout_seconds: int | None = None,
    ) -> Optional[Dict[str, Any]]:
        """Poll RTDB until the incident is resolved or timeout expires."""
        timeout = timeout_seconds or settings.QUARANTINE_TIMEOUT
        deadline = time.monotonic() + timeout
        url = f"{settings.FIREBASE_DATABASE_URL.rstrip('/')}/incidents/{incident_id}.json"

        async with httpx.AsyncClient(timeout=10.0) as client:
            while time.monotonic() < deadline:
                if self._app is not None:
                    record = await self.async_get_incident(incident_id)
                else:
                    try:
                        resp = await client.get(url)
                        record = resp.json() if resp.status_code == 200 else self._local_cache.get(incident_id)
                    except Exception:
                        record = self._local_cache.get(incident_id)

                if record and record.get("status") in ("APPROVED_RAW", "APPROVED_SANITIZED", "REJECTED"):
                    logger.info("Live resolution detected for incident %s: %s (via %s)", incident_id, record.get("status"), record.get("resolved_by"))
                    return record

                await asyncio.sleep(settings.QUARANTINE_POLL_INTERVAL)
        return None


firebase_manager = FirebaseManager()
