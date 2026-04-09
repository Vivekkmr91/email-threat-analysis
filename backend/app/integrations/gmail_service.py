import base64
import json
import time
import asyncio
from typing import Any, Dict, List

import httpx
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"

_TOKEN_CACHE = {
    "access_token": None,
    "expires_at": 0.0,
}
_TOKEN_LOCK = asyncio.Lock()


class GmailIntegrationError(Exception):
    pass


def _decode_pubsub_data(data: str) -> Dict[str, Any]:
    try:
        decoded = base64.b64decode(data).decode("utf-8")
        return json.loads(decoded)
    except Exception as exc:
        raise GmailIntegrationError(f"Invalid Pub/Sub payload: {exc}")


async def _get_gmail_access_token() -> str:
    if settings.GMAIL_ACCESS_TOKEN:
        return settings.GMAIL_ACCESS_TOKEN

    if not (settings.GMAIL_REFRESH_TOKEN and settings.GMAIL_CLIENT_ID and settings.GMAIL_CLIENT_SECRET):
        raise GmailIntegrationError("Gmail OAuth refresh credentials are not configured")

    now = time.time()
    cached = _TOKEN_CACHE.get("access_token")
    if cached and _TOKEN_CACHE.get("expires_at", 0) - 60 > now:
        return cached

    async with _TOKEN_LOCK:
        cached = _TOKEN_CACHE.get("access_token")
        if cached and _TOKEN_CACHE.get("expires_at", 0) - 60 > time.time():
            return cached

        payload = {
            "client_id": settings.GMAIL_CLIENT_ID,
            "client_secret": settings.GMAIL_CLIENT_SECRET,
            "refresh_token": settings.GMAIL_REFRESH_TOKEN,
            "grant_type": "refresh_token",
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(settings.GMAIL_TOKEN_URI, data=payload)
            if response.status_code != 200:
                raise GmailIntegrationError(f"Gmail token refresh failed: {response.text}")
            data = response.json()

        access_token = data.get("access_token")
        expires_in = int(data.get("expires_in", 3600))
        if not access_token:
            raise GmailIntegrationError("Gmail token refresh did not return access_token")

        _TOKEN_CACHE["access_token"] = access_token
        _TOKEN_CACHE["expires_at"] = time.time() + expires_in
        return access_token


async def fetch_history_message_ids(history_id: str) -> List[str]:
    access_token = await _get_gmail_access_token()

    url = f"{GMAIL_API_BASE}/users/{settings.GMAIL_USER_ID}/history"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"startHistoryId": history_id}

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url, headers=headers, params=params)
        if response.status_code != 200:
            raise GmailIntegrationError(f"Gmail history fetch failed: {response.text}")
        payload = response.json()

    message_ids = []
    for history in payload.get("history", []):
        for msg in history.get("messagesAdded", []):
            if msg.get("message", {}).get("id"):
                message_ids.append(msg["message"]["id"])
        for msg in history.get("messages", []):
            if msg.get("id"):
                message_ids.append(msg["id"])

    return list(dict.fromkeys(message_ids))


async def fetch_raw_message(message_id: str) -> str:
    access_token = await _get_gmail_access_token()

    url = f"{GMAIL_API_BASE}/users/{settings.GMAIL_USER_ID}/messages/{message_id}"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"format": "raw"}

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url, headers=headers, params=params)
        if response.status_code != 200:
            raise GmailIntegrationError(f"Gmail message fetch failed: {response.text}")
        payload = response.json()

    raw_data = payload.get("raw")
    if not raw_data:
        raise GmailIntegrationError("Gmail message payload missing raw content")

    try:
        return base64.urlsafe_b64decode(raw_data.encode("utf-8")).decode("utf-8", errors="replace")
    except Exception as exc:
        raise GmailIntegrationError(f"Failed to decode raw email: {exc}")


async def parse_pubsub_notification(payload: Dict[str, Any]) -> List[str]:
    message = payload.get("message", {})
    data = message.get("data")
    if not data:
        raise GmailIntegrationError("Pub/Sub payload missing data")

    decoded = _decode_pubsub_data(data)
    history_id = str(decoded.get("historyId", ""))
    if not history_id:
        raise GmailIntegrationError("Pub/Sub payload missing historyId")

    return await fetch_history_message_ids(history_id)
