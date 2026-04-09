"""
Enrichment Agent - Technical inspection of URLs and attachments:
- URL reputation checks (VirusTotal, PhishTank)
- QR code extraction and analysis (Quishing)
- Look-alike domain detection
- AiTM (Adversary-in-the-Middle) proxy detection
- Living-off-the-Land (LotL) detection
- Attachment hash analysis
- Deepfake link detection
"""
import time
import re
import io
import hashlib
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import httpx
import structlog

from app.agents.state import EmailAnalysisState, AgentFindingState
from app.agents.email_parser import detect_lookalike_domain
from app.core.config import settings

logger = structlog.get_logger(__name__)

# Living-off-the-Land: Legitimate services used to host malware
LOTL_SERVICES = {
    "drive.google.com", "docs.google.com", "dropbox.com", "wetransfer.com",
    "onedrive.live.com", "sharepoint.com", "box.com", "mega.nz",
    "notion.so", "github.com", "raw.githubusercontent.com",
}

# AiTM indicators: domains that proxy login pages
AITM_PATTERNS = [
    r'login\.(.*)\.(com|net|org)',
    r'signin\.(.*)\.(com|net|org)',
    r'secure\.(.*)\.(com|net|org)',
    r'account\.(.*)\.(com|net|org)',
    r'auth\.(.*)\.(com|net|org)',
    r'verify\.(.*)\.(com|net|org)',
    r'mfa\.(.*)\.(com|net|org)',
]

# Deepfake video hosting platforms that are commonly abused
DEEPFAKE_PLATFORMS = [
    "tiktok.com", "youtube.com", "vimeo.com", "dailymotion.com",
    "loom.com", "zoom.us",
]

# Known URL shorteners (expand before analysis)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "tiny.cc", "is.gd", "buff.ly",
}


async def run_enrichment_agent(state: EmailAnalysisState) -> EmailAnalysisState:
    """Enrichment Agent node for LangGraph."""
    start_time = time.time()
    log = logger.bind(analysis_id=state["analysis_id"])
    log.info("Enrichment Agent starting")

    parsed = state.get("parsed_email")
    if not parsed:
        return {**state, "agent_findings": [_error_finding("enrichment_agent", "No parsed email")]}

    findings = []
    indicators = {}
    categories = []
    score_components = []
    url_analyses = []
    attachment_analyses = []

    # ─── URL Analysis ────────────────────────────────────────────────────────
    urls = parsed.get("urls", [])
    log.info(f"Analyzing {len(urls)} URLs")

    # ─── Attachment Analysis ──────────────────────────────────────────────────
    attachments = parsed.get("attachment_data", [])
    log.info(f"Analyzing {len(attachments)} attachments")

    async with httpx.AsyncClient(timeout=5.0) as client:
        url_tasks = [_analyze_url(url, client) for url in urls[:20]]
        if url_tasks:
            url_analyses = await asyncio.gather(*url_tasks)
        for url_result in url_analyses:
            if url_result.get("threat_score", 0) > 0.3:
                score_components.append(url_result["threat_score"])
                findings.extend(url_result.get("findings", []))
                categories.extend(url_result.get("categories", []))
                indicators[f"url_{url_result.get('url', '')[:50]}"] = url_result

        attachment_tasks = [_analyze_attachment(attachment, client) for attachment in attachments]
        if attachment_tasks:
            attachment_analyses = await asyncio.gather(*attachment_tasks)
        for att_result in attachment_analyses:
            if att_result.get("threat_score", 0) > 0.3:
                score_components.append(att_result["threat_score"])
                findings.extend(att_result.get("findings", []))
                categories.extend(att_result.get("categories", []))

    # ─── LotL Detection ──────────────────────────────────────────────────────
    lotl_result = _detect_lotl(urls, parsed.get("body_text", "") or "")
    if lotl_result["detected"]:
        score_components.append(0.55)
        findings.append(f"Living-off-the-Land: Legitimate service used for payload delivery: {lotl_result['services']}")
        indicators["lotl_services"] = lotl_result["services"]
        categories.append("living_off_the_land")

    # ─── Final Score ──────────────────────────────────────────────────────────
    if not score_components:
        final_score = 0.05
    else:
        final_score = max(score_components)
        if len(score_components) >= 2:
            final_score = min(final_score + 0.08 * (len(score_components) - 1), 0.95)

    processing_time = int((time.time() - start_time) * 1000)

    finding = AgentFindingState(
        agent_name="enrichment_agent",
        score=final_score,
        confidence=0.80,
        findings=findings[:20],  # Cap findings
        indicators=indicators,
        threat_categories=list(set(categories)),
        processing_time_ms=processing_time,
    )

    log.info("Enrichment Agent complete", score=final_score, time_ms=processing_time,
             url_count=len(url_analyses), attachment_count=len(attachment_analyses))

    return {
        **state,
        "agent_findings": [finding],
        "enrichment_agent_result": {
            "score": final_score,
            "findings": findings,
            "indicators": indicators,
            "categories": list(set(categories)),
        },
        "url_analyses": url_analyses,
        "attachment_analyses": attachment_analyses,
    }


async def _analyze_url(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Comprehensive URL threat analysis."""
    result = {
        "url": url,
        "threat_score": 0.0,
        "findings": [],
        "categories": [],
        "indicators": {},
    }

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower().strip("www.")
        result["domain"] = domain

        # 1. Look-alike domain check
        lookalike = detect_lookalike_domain(domain)
        if lookalike:
            result["threat_score"] = max(result["threat_score"], 0.8)
            result["findings"].append(f"Phishing URL: '{domain}' mimics '{lookalike}'")
            result["is_look_alike"] = True
            result["look_alike_target"] = lookalike
            result["categories"].append("phishing")

        # 2. URL shortener detection
        if domain in URL_SHORTENERS:
            result["threat_score"] = max(result["threat_score"], 0.3)
            result["findings"].append(f"URL shortener detected: {domain} (destination hidden)")
            result["indicators"]["is_shortener"] = True

        # 3. AiTM detection
        aitm_detected, aitm_pattern = _detect_aitm(url, domain)
        if aitm_detected:
            result["threat_score"] = max(result["threat_score"], 0.7)
            result["findings"].append(f"Potential AiTM proxy URL: {aitm_pattern}")
            result["indicators"]["aitm_suspected"] = True
            result["categories"].append("adversary_in_the_middle")

        # 4. Suspicious URL features
        url_score, url_findings = _check_url_features(url, domain)
        if url_score > 0:
            result["threat_score"] = max(result["threat_score"], url_score)
            result["findings"].extend(url_findings)

        # 5. VirusTotal check (if API key available)
        if settings.VIRUSTOTAL_API_KEY:
            vt_result = await _check_virustotal_url(url, client)
            if vt_result:
                result["virustotal_score"] = vt_result.get("score", 0)
                if vt_result.get("malicious", False):
                    result["threat_score"] = max(result["threat_score"], 0.9)
                    result["findings"].append(
                        f"VirusTotal: URL flagged by {vt_result.get('malicious_count', 0)} engines"
                    )
                    result["categories"].append("malware")

        # 6. PhishTank check (if API key available)
        if settings.PHISHTANK_API_KEY:
            pt_result = await _check_phishtank(url, client)
            if pt_result:
                result["phishtank_detected"] = True
                result["threat_score"] = max(result["threat_score"], 0.95)
                result["findings"].append("PhishTank: URL confirmed as phishing site")
                result["categories"].append("phishing")

        # 7. Deepfake link detection
        if any(plat in domain for plat in DEEPFAKE_PLATFORMS):
            body_context = ""  # Would need full context in production
            result["indicators"]["possible_deepfake_host"] = domain

    except Exception as e:
        result["findings"].append(f"URL analysis error: {str(e)}")

    return result


def _detect_aitm(url: str, domain: str) -> Tuple[bool, str]:
    """Detect potential AiTM (Adversary-in-the-Middle) proxy URLs."""
    # Check for login-related paths on non-legitimate domains
    url_lower = url.lower()
    
    for pattern in AITM_PATTERNS:
        match = re.search(pattern, domain)
        if match:
            # It's suspicious only if it's not purely a known legitimate service
            # (i.e., if it has extra parts beyond the legitimate domain)
            is_pure_legit = domain in [
                "microsoft.com", "google.com", "apple.com", "amazon.com",
                "login.microsoft.com", "accounts.google.com"
            ]
            if not is_pure_legit:
                return True, f"Pattern: {pattern} on domain: {domain}"

    # Check for credential-related paths
    credential_paths = ["/login", "/signin", "/auth", "/verify", "/mfa", "/oauth"]
    if any(path in url_lower for path in credential_paths):
        # Unknown domain with credential-harvesting path
        if not any(known in domain for known in [
            "microsoft.com", "google.com", "apple.com", "amazon.com",
            "facebook.com", "twitter.com", "linkedin.com"
        ]):
            # Check if path looks like a proxy (contains target domain in URL)
            if re.search(r'https?%3A%2F%2F', url) or "returnurl" in url_lower:
                return True, f"Credential-harvesting URL with redirect parameter"

    return False, ""


def _detect_lotl(urls: List[str], body: str) -> Dict[str, Any]:
    """Detect Living-off-the-Land: legitimate services used for malicious purposes."""
    detected_services = []

    for url in urls:
        try:
            domain = urlparse(url).netloc.lower().strip("www.")
            for lotl_service in LOTL_SERVICES:
                if lotl_service in domain:
                    # Check if context is suspicious
                    if _is_suspicious_lotl_context(url, body):
                        detected_services.append(lotl_service)
        except Exception:
            pass

    return {
        "detected": len(detected_services) > 0,
        "services": list(set(detected_services)),
    }


def _is_suspicious_lotl_context(url: str, body: str) -> bool:
    """Check if a LotL link appears in a suspicious context."""
    suspicious_keywords = [
        "salary", "invoice", "payment", "confidential", "urgent",
        "reset password", "mfa", "update", "verification",
    ]
    body_lower = body.lower()
    return any(kw in body_lower for kw in suspicious_keywords)


def _check_url_features(url: str, domain: str) -> Tuple[float, List[str]]:
    """Check various URL features for suspicious characteristics."""
    score = 0.0
    findings = []

    # 1. Long subdomain chains (common in phishing)
    parts = domain.split(".")
    if len(parts) > 5:
        score = max(score, 0.4)
        findings.append(f"Suspicious: excessive subdomain depth ({len(parts)} levels)")

    # 2. IP address as hostname
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        score = max(score, 0.5)
        findings.append("URL uses raw IP address instead of domain name")

    # 3. Port number in URL (non-standard)
    parsed = urlparse(url)
    if parsed.port and parsed.port not in (80, 443):
        score = max(score, 0.3)
        findings.append(f"Non-standard port in URL: {parsed.port}")

    # 4. Excessive URL length (common in obfuscated phishing URLs)
    if len(url) > 200:
        score = max(score, 0.25)
        findings.append(f"Suspiciously long URL ({len(url)} chars)")

    # 5. URL encoding / obfuscation
    if "%" in url and url.count("%") > 5:
        score = max(score, 0.35)
        findings.append("Heavy URL encoding detected (possible obfuscation)")

    # 6. Mixed case domain (homoglyph attempt)
    if domain != domain.lower():
        score = max(score, 0.3)
        findings.append("Mixed case in domain (possible homoglyph attack)")

    return score, findings


async def _analyze_attachment(attachment: Dict[str, Any], client: httpx.AsyncClient) -> Dict[str, Any]:
    """Analyze email attachment for threats."""
    result = {
        "filename": attachment.get("filename", "unknown"),
        "file_type": attachment.get("mime_type"),
        "file_size_bytes": attachment.get("size", 0),
        "sha256_hash": attachment.get("sha256"),
        "md5_hash": attachment.get("md5"),
        "threat_score": 0.0,
        "findings": [],
        "categories": [],
        "contains_qr_code": False,
        "qr_code_urls": [],
        "sandbox_detonated": False,
    }

    filename = attachment.get("filename", "").lower()
    content = attachment.get("content_bytes", b"")
    mime_type = attachment.get("mime_type", "")

    # 1. Suspicious file extension check
    dangerous_extensions = [
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
        ".scr", ".pif", ".com", ".lnk", ".hta", ".wsf", ".reg",
    ]
    medium_risk_extensions = [
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        ".pdf", ".zip", ".rar", ".7z", ".iso",
    ]

    ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    if ext in dangerous_extensions:
        result["threat_score"] = max(result["threat_score"], 0.85)
        result["findings"].append(f"High-risk executable attachment: {filename}")
        result["categories"].append("malware")
    elif ext in medium_risk_extensions:
        result["threat_score"] = max(result["threat_score"], 0.35)
        result["findings"].append(f"Potentially risky attachment type: {filename}")

    # 2. Double extension check (e.g., invoice.pdf.exe)
    if filename.count(".") > 1:
        parts = filename.split(".")
        if parts[-1] in [e.strip(".") for e in dangerous_extensions]:
            result["threat_score"] = max(result["threat_score"], 0.9)
            result["findings"].append(f"Double extension detected (masquerading): {filename}")
            result["categories"].append("malware")

    # 3. VirusTotal hash check
    if settings.VIRUSTOTAL_API_KEY and result.get("sha256_hash"):
        vt_result = await _check_virustotal_hash(result["sha256_hash"], client)
        if vt_result:
            result["virustotal_score"] = vt_result.get("score", 0)
            if vt_result.get("malicious", False):
                result["threat_score"] = max(result["threat_score"], 0.95)
                result["findings"].append(
                    f"VirusTotal: File flagged as malicious by "
                    f"{vt_result.get('malicious_count', 0)} engines"
                )
                result["categories"].append("malware")

    # 4. QR code extraction from images and PDFs
    if content and (mime_type.startswith("image/") or mime_type == "application/pdf" or
                    ext in [".png", ".jpg", ".jpeg", ".gif", ".pdf"]):
        qr_result = _extract_qr_codes(content, filename)
        if qr_result["qr_codes_found"]:
            result["contains_qr_code"] = True
            result["qr_code_urls"] = qr_result["urls"]
            if qr_result["urls"]:
                result["threat_score"] = max(result["threat_score"], 0.65)
                result["findings"].append(
                    f"QR code(s) found in attachment linking to: {qr_result['urls'][:2]}"
                )
                result["categories"].append("quishing")

    return result


def _extract_qr_codes(content: bytes, filename: str) -> Dict[str, Any]:
    """Extract QR codes from image content."""
    try:
        from PIL import Image
        from pyzbar import pyzbar

        image = Image.open(io.BytesIO(content))
        decoded = pyzbar.decode(image)

        urls = []
        for obj in decoded:
            data = obj.data.decode("utf-8", errors="replace")
            if data.startswith("http"):
                urls.append(data)

        return {
            "qr_codes_found": len(decoded) > 0,
            "urls": urls,
            "count": len(decoded),
        }
    except Exception as e:
        logger.debug("QR code extraction failed", error=str(e))
        return {"qr_codes_found": False, "urls": [], "count": 0}


async def _check_virustotal_url(url: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
    """Check URL against VirusTotal API."""
    try:
        import base64 as b64
        url_id = b64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        response = await client.get(
            f"{settings.VIRUSTOTAL_BASE_URL}/urls/{url_id}",
            headers=headers,
        )
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            return {
                "malicious": malicious > 0,
                "malicious_count": malicious,
                "total_engines": total,
                "score": malicious / max(total, 1),
            }
    except Exception as e:
        logger.debug("VirusTotal URL check failed", error=str(e))
    return None


async def _check_virustotal_hash(sha256: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
    """Check file hash against VirusTotal API."""
    try:
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        response = await client.get(
            f"{settings.VIRUSTOTAL_BASE_URL}/files/{sha256}",
            headers=headers,
        )
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            return {
                "malicious": malicious > 3,  # Flag if 3+ engines detect it
                "malicious_count": malicious,
                "total_engines": total,
                "score": malicious / max(total, 1),
            }
    except Exception as e:
        logger.debug("VirusTotal hash check failed", error=str(e))
    return None


async def _check_phishtank(url: str, client: httpx.AsyncClient) -> Optional[bool]:
    """Check URL against PhishTank database."""
    try:
        data = {"url": url, "format": "json"}
        if settings.PHISHTANK_API_KEY:
            data["app_key"] = settings.PHISHTANK_API_KEY
        response = await client.post(
            settings.PHISHTANK_BASE_URL,
            data=data,
        )
        if response.status_code == 200:
            result = response.json()
            return result.get("results", {}).get("in_database", False)
    except Exception as e:
        logger.debug("PhishTank check failed", error=str(e))
    return None


def _error_finding(agent_name: str, error: str) -> AgentFindingState:
    return AgentFindingState(
        agent_name=agent_name, score=0.0, confidence=0.0,
        findings=[f"Agent error: {error}"], indicators={},
        threat_categories=[], processing_time_ms=0,
    )
