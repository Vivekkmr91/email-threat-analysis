from typing import Any, Dict, List, Set
import asyncio
import ipaddress
import time
from urllib.parse import urlparse

import httpx
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

_OPENPHISH_CACHE: Dict[str, Any] = {
    "expires_at": 0.0,
    "urls": set(),
}


async def _load_openphish_feed(client: httpx.AsyncClient) -> Set[str]:
    if not settings.OPENPHISH_FEED_URL:
        return set()

    now = time.time()
    cached_urls: Set[str] = _OPENPHISH_CACHE.get("urls", set())
    if cached_urls and _OPENPHISH_CACHE.get("expires_at", 0) > now:
        return cached_urls

    try:
        response = await client.get(settings.OPENPHISH_FEED_URL, timeout=15.0)
        if response.status_code != 200:
            logger.warning("OpenPhish feed fetch failed", status=response.status_code)
            return cached_urls

        urls = {line.strip() for line in response.text.splitlines() if line.strip().startswith("http")}
        _OPENPHISH_CACHE["urls"] = urls
        _OPENPHISH_CACHE["expires_at"] = now + settings.OPENPHISH_FEED_TTL_SECONDS
        return urls
    except Exception as exc:
        logger.warning("OpenPhish feed fetch error", error=str(exc))
        return cached_urls


async def _query_urlhaus(client: httpx.AsyncClient, url: str) -> Dict[str, Any] | None:
    try:
        response = await client.post(settings.URLHAUS_API_URL, data={"url": url}, timeout=10.0)
        if response.status_code != 200:
            return None
        data = response.json()
        if data.get("query_status") != "ok":
            return None
        url_status = data.get("url_status")
        if url_status not in {"online", "offline"}:
            return None
        return {
            "source": "urlhaus",
            "type": "url",
            "indicator": url,
            "status": url_status,
            "threat": data.get("threat"),
            "confidence": 0.85 if url_status == "online" else 0.65,
        }
    except Exception as exc:
        logger.warning("URLhaus lookup error", error=str(exc))
        return None


async def _query_abuseipdb(client: httpx.AsyncClient, ip_address: str) -> Dict[str, Any] | None:
    if not settings.ABUSEIPDB_API_KEY:
        return None

    try:
        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": "",
        }
        response = await client.get(settings.ABUSEIPDB_BASE_URL, headers=headers, params=params, timeout=10.0)
        if response.status_code != 200:
            return None
        data = response.json().get("data", {})
        score = float(data.get("abuseConfidenceScore", 0))
        if score < 25:
            return None
        return {
            "source": "abuseipdb",
            "type": "ip",
            "indicator": ip_address,
            "confidence": min(score / 100, 1.0),
            "report_count": data.get("totalReports"),
        }
    except Exception as exc:
        logger.warning("AbuseIPDB lookup error", error=str(exc))
        return None


async def query_threat_feeds(
    client: httpx.AsyncClient,
    urls: List[str],
    domains: List[str],
    hashes: List[str],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    headers = {}
    if settings.THREAT_FEED_API_KEY:
        headers["Authorization"] = f"Bearer {settings.THREAT_FEED_API_KEY}"

    payload = {
        "urls": urls,
        "domains": domains,
        "hashes": hashes,
    }

    for feed_url in settings.THREAT_FEED_URLS:
        try:
            response = await client.post(feed_url, json=payload, headers=headers, timeout=10.0)
            if response.status_code != 200:
                logger.warning("Threat feed lookup failed", feed_url=feed_url, status=response.status_code)
                continue
            data = response.json()
            matches = data.get("matches", []) if isinstance(data, dict) else []
            for match in matches:
                match["source"] = match.get("source") or feed_url
                results.append(match)
        except Exception as exc:
            logger.warning("Threat feed lookup error", feed_url=feed_url, error=str(exc))

    if settings.OPENPHISH_FEED_URL and urls:
        openphish_urls = await _load_openphish_feed(client)
        for url in urls:
            if url in openphish_urls:
                results.append({
                    "source": "openphish",
                    "type": "url",
                    "indicator": url,
                    "confidence": 0.9,
                })

    if urls:
        urlhaus_tasks = [_query_urlhaus(client, url) for url in urls[:10]]
        if urlhaus_tasks:
            for result in await asyncio.gather(*urlhaus_tasks):
                if result:
                    results.append(result)

    ip_candidates: Set[str] = set()
    for domain in domains:
        try:
            ip_candidates.add(str(ipaddress.ip_address(domain)))
        except ValueError:
            continue

    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname:
                ip_candidates.add(str(ipaddress.ip_address(hostname)))
        except ValueError:
            continue

    if ip_candidates and settings.ABUSEIPDB_API_KEY:
        ip_tasks = [_query_abuseipdb(client, ip) for ip in list(ip_candidates)[:10]]
        for result in await asyncio.gather(*ip_tasks):
            if result:
                results.append(result)

    return results
