"""
Email Parser - Ingests and parses raw emails into structured components.
Supports RFC 2822 raw emails and structured dict input.
"""
import email
import email.policy
import re
import hashlib
import base64
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import structlog

from app.agents.state import ParsedEmail, EmailAnalysisState

logger = structlog.get_logger(__name__)

# URL regex pattern
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)

# Common lookalike characters mapping for homoglyph detection
LOOKALIKE_MAP = {
    'paypa1': 'paypal', 'paypai': 'paypal', 'micros0ft': 'microsoft',
    'microsofft': 'microsoft', 'arnazon': 'amazon', 'amazzon': 'amazon',
    'g00gle': 'google', 'gooogle': 'google', 'faceb00k': 'facebook',
    'bankofamerica': 'bankofamerica', 'banc-of-america': 'bankofamerica',
    'wellsfarg0': 'wellsfargo', 'chas3': 'chase',
}


def parse_email_content(state: EmailAnalysisState) -> EmailAnalysisState:
    """
    Parse raw email or email dict into structured ParsedEmail state.
    This is the first node in the LangGraph pipeline.
    """
    log = logger.bind(analysis_id=state["analysis_id"])
    log.info("Starting email parsing")

    try:
        if state.get("raw_email"):
            parsed = _parse_raw_email(state["raw_email"])
        elif state.get("email_dict"):
            parsed = _parse_email_dict(state["email_dict"])
        else:
            raise ValueError("No email content provided")

        return {
            **state,
            "parsed_email": parsed,
            "errors": []
        }

    except Exception as e:
        log.error("Email parsing failed", error=str(e))
        return {
            **state,
            "parsed_email": None,
            "errors": [f"Email parsing error: {str(e)}"]
        }


def _parse_raw_email(raw_email: str) -> ParsedEmail:
    """Parse RFC 2822 formatted email string."""
    msg = email.message_from_string(raw_email, policy=email.policy.default)
    return _extract_from_message(msg)


def _parse_email_dict(email_dict: Dict[str, Any]) -> ParsedEmail:
    """Parse structured email dict (from API input)."""
    subject = email_dict.get("subject", "")
    sender = email_dict.get("sender", "")
    recipients = email_dict.get("recipients", [])
    body_text = email_dict.get("body_text", "")
    body_html = email_dict.get("body_html", "")
    headers = email_dict.get("headers", {})
    attachments_raw = email_dict.get("attachments_base64", [])

    # Extract sender details
    sender_email, sender_name = _parse_email_address(sender)
    reply_to = headers.get("Reply-To", headers.get("reply-to"))
    if reply_to:
        reply_to, _ = _parse_email_address(reply_to)

    # Extract URLs from body
    urls = []
    if body_text:
        urls.extend(URL_PATTERN.findall(body_text))
    if body_html:
        urls.extend(_extract_urls_from_html(body_html))
        if not body_text:
            body_text = BeautifulSoup(body_html, "html.parser").get_text(separator=" ")

    urls = list(set(urls))

    # Process attachments
    attachments = []
    attachment_filenames = []
    for att in attachments_raw:
        filename = att.get("filename", "unknown")
        content_b64 = att.get("content_base64", "")
        mime_type = att.get("mime_type", "application/octet-stream")
        try:
            content_bytes = base64.b64decode(content_b64) if content_b64 else b""
        except Exception:
            content_bytes = b""

        attachments.append({
            "filename": filename,
            "content_bytes": content_bytes,
            "mime_type": mime_type,
            "sha256": hashlib.sha256(content_bytes).hexdigest() if content_bytes else None,
            "md5": hashlib.md5(content_bytes).hexdigest() if content_bytes else None,
            "size": len(content_bytes),
        })
        attachment_filenames.append(filename)

    return ParsedEmail(
        message_id=headers.get("Message-ID"),
        subject=subject,
        sender_email=sender_email,
        sender_display_name=sender_name,
        recipient_emails=recipients if isinstance(recipients, list) else [recipients],
        reply_to=reply_to,
        raw_headers=dict(headers),
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachment_filenames=attachment_filenames,
        attachment_data=attachments,
        received_chain=_extract_received_chain(headers),
        date_sent=headers.get("Date"),
    )


def _extract_from_message(msg) -> ParsedEmail:
    """Extract components from a Python email.message.Message object."""
    # Headers
    headers = dict(msg.items())

    # Sender
    from_header = msg.get("From", "")
    sender_email, sender_name = _parse_email_address(from_header)

    # Reply-To
    reply_to_header = msg.get("Reply-To", "")
    reply_to_email, _ = _parse_email_address(reply_to_header) if reply_to_header else (None, None)

    # Recipients
    recipients = []
    for field in ["To", "Cc"]:
        val = msg.get(field, "")
        if val:
            for addr in val.split(","):
                em, _ = _parse_email_address(addr.strip())
                if em:
                    recipients.append(em)

    # Body
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and not body_text:
                body_text = _decode_payload(part)
            elif content_type == "text/html" and not body_html:
                body_html = _decode_payload(part)
    else:
        content_type = msg.get_content_type()
        if content_type == "text/html":
            body_html = _decode_payload(msg)
            body_text = BeautifulSoup(body_html, "html.parser").get_text(separator=" ")
        else:
            body_text = _decode_payload(msg)

    # Extract URLs
    urls = []
    if body_text:
        urls.extend(URL_PATTERN.findall(body_text))
    if body_html:
        urls.extend(_extract_urls_from_html(body_html))
    urls = list(set(urls))

    # Attachments
    attachments = []
    attachment_filenames = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "unknown"
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename,
                "content_bytes": payload,
                "mime_type": part.get_content_type(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "md5": hashlib.md5(payload).hexdigest(),
                "size": len(payload),
            })
            attachment_filenames.append(filename)

    return ParsedEmail(
        message_id=msg.get("Message-ID"),
        subject=msg.get("Subject", ""),
        sender_email=sender_email,
        sender_display_name=sender_name,
        recipient_emails=recipients,
        reply_to=reply_to_email,
        raw_headers=headers,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachment_filenames=attachment_filenames,
        attachment_data=attachments,
        received_chain=_extract_received_chain(headers),
        date_sent=msg.get("Date"),
    )


def _decode_payload(part) -> str:
    """Safely decode email payload."""
    try:
        payload = part.get_payload(decode=True)
        if payload:
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
    except Exception:
        pass
    return ""


def _parse_email_address(address: str):
    """Extract email and display name from address string."""
    if not address:
        return None, None
    match = re.search(r'<([^>]+)>', address)
    if match:
        email_addr = match.group(1).strip().lower()
        name = address[:address.find('<')].strip().strip('"')
    else:
        email_addr = address.strip().lower()
        name = None
    return email_addr or None, name or None


def _extract_urls_from_html(html: str) -> List[str]:
    """Extract all URLs from HTML content."""
    urls = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(['a', 'img', 'iframe', 'form']):
            for attr in ['href', 'src', 'action']:
                url = tag.get(attr)
                if url and url.startswith('http'):
                    urls.append(url)
        # Also regex scan
        urls.extend(URL_PATTERN.findall(html))
    except Exception:
        pass
    return urls


def _extract_received_chain(headers: Dict[str, str]) -> List[str]:
    """Extract the Received header chain."""
    received = []
    for key, val in headers.items():
        if key.lower() == "received":
            received.append(val)
    return received


def detect_lookalike_domain(domain: str) -> Optional[str]:
    """Check if a domain looks like a legitimate domain (homoglyph/typosquatting)."""
    domain_lower = domain.lower().replace('.com', '').replace('.net', '').replace('.org', '')
    for fake, real in LOOKALIKE_MAP.items():
        if fake in domain_lower:
            return real
    return None
