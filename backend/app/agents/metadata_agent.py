"""
Metadata Agent - Analyzes email headers and authentication:
- SPF / DKIM / DMARC verification
- Header anomaly detection
- Routing path analysis
- Sender domain reputation
- Look-alike domain detection (typosquatting / homoglyph)
- IP geolocation and reputation
"""
import time
import re
import socket
import asyncio
from typing import Dict, Any, List, Optional, Tuple
import dns.resolver
import dns.exception
import structlog

from app.agents.state import EmailAnalysisState, AgentFindingState
from app.agents.email_parser import detect_lookalike_domain

logger = structlog.get_logger(__name__)

# Known legitimate domains that are commonly spoofed
HIGH_VALUE_DOMAINS = {
    "paypal.com", "google.com", "microsoft.com", "amazon.com", "apple.com",
    "facebook.com", "twitter.com", "linkedin.com", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "citibank.com", "irs.gov",
}

# Suspicious TLDs used in phishing
SUSPICIOUS_TLDS = {'.xyz', '.top', '.click', '.link', '.online', '.site', '.tk', '.ml', '.ga', '.cf'}

# Free email providers (suspicious for BEC)
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com",
    "guerrillamail.com", "mailinator.com", "tempmail.com", "10minutemail.com",
}


def run_metadata_agent(state: EmailAnalysisState) -> EmailAnalysisState:
    """Metadata Analysis Agent node for LangGraph."""
    start_time = time.time()
    log = logger.bind(analysis_id=state["analysis_id"])
    log.info("Metadata Agent starting")

    parsed = state.get("parsed_email")
    if not parsed:
        return {**state, "agent_findings": [_error_finding("metadata_agent", "No parsed email")]}

    findings = []
    indicators = {}
    categories = []
    score_components = []

    # 1. SPF/DKIM/DMARC check from headers
    auth_result = _check_email_authentication(parsed)
    findings.extend(auth_result["findings"])
    indicators.update(auth_result["indicators"])
    if auth_result["score"] > 0:
        score_components.append(auth_result["score"])
        categories.extend(auth_result["categories"])

    # 2. Sender domain analysis
    sender_domain_result = _analyze_sender_domain(parsed)
    findings.extend(sender_domain_result["findings"])
    indicators.update(sender_domain_result["indicators"])
    if sender_domain_result["score"] > 0:
        score_components.append(sender_domain_result["score"])
        categories.extend(sender_domain_result["categories"])

    # 3. Header anomaly detection
    header_result = _analyze_header_anomalies(parsed)
    findings.extend(header_result["findings"])
    indicators.update(header_result["indicators"])
    if header_result["score"] > 0:
        score_components.append(header_result["score"])
        categories.extend(header_result["categories"])

    # 4. Routing path analysis
    routing_result = _analyze_routing(parsed)
    findings.extend(routing_result["findings"])
    indicators.update(routing_result["indicators"])
    if routing_result["score"] > 0:
        score_components.append(routing_result["score"])
        categories.extend(routing_result["categories"])

    # Calculate final score
    if not score_components:
        final_score = 0.05
    else:
        final_score = max(score_components)
        # Compound scoring: multiple anomalies increase confidence
        if len(score_components) >= 2:
            final_score = min(final_score + 0.1 * (len(score_components) - 1), 0.95)

    processing_time = int((time.time() - start_time) * 1000)

    finding = AgentFindingState(
        agent_name="metadata_agent",
        score=final_score,
        confidence=0.85,
        findings=findings,
        indicators=indicators,
        threat_categories=list(set(categories)),
        processing_time_ms=processing_time,
    )

    log.info("Metadata Agent complete", score=final_score, time_ms=processing_time)

    return {
        **state,
        "agent_findings": [finding],
        "metadata_agent_result": {
            "score": final_score,
            "findings": findings,
            "indicators": indicators,
            "categories": list(set(categories)),
        },
        "spf_result": indicators.get("spf_result"),
        "dkim_result": indicators.get("dkim_result"),
        "dmarc_result": indicators.get("dmarc_result"),
    }


def _check_email_authentication(parsed: Dict) -> Dict[str, Any]:
    """Check SPF, DKIM, DMARC results from headers."""
    headers = parsed.get("raw_headers", {})
    findings = []
    indicators = {}
    categories = []
    score = 0.0

    # Check Authentication-Results header
    auth_results = headers.get("Authentication-Results", headers.get("authentication-results", ""))
    auth_lower = auth_results.lower()

    spf_result = _extract_auth_result(auth_lower, "spf")
    dkim_result = _extract_auth_result(auth_lower, "dkim")
    dmarc_result = _extract_auth_result(auth_lower, "dmarc")

    indicators["spf_result"] = spf_result
    indicators["dkim_result"] = dkim_result
    indicators["dmarc_result"] = dmarc_result

    failed_checks = []
    if spf_result == "fail":
        failed_checks.append("SPF")
        score = max(score, 0.6)
    elif spf_result == "softfail":
        failed_checks.append("SPF (softfail)")
        score = max(score, 0.35)

    if dkim_result == "fail":
        failed_checks.append("DKIM")
        score = max(score, 0.6)

    if dmarc_result == "fail":
        failed_checks.append("DMARC")
        score = max(score, 0.7)

    if failed_checks:
        findings.append(f"Email authentication failed: {', '.join(failed_checks)}")
        categories.append("phishing")
    elif spf_result == "pass" and dkim_result == "pass":
        findings.append("Email authentication passed: SPF ✓ DKIM ✓")

    # Check for no authentication headers at all
    if not auth_results:
        score = max(score, 0.2)
        findings.append("No Authentication-Results header found")

    # Check ARC (Anti-spam Research Chain) for forwarded emails
    arc_seal = headers.get("ARC-Seal", "")
    if arc_seal:
        indicators["has_arc_seal"] = True

    return {"score": score, "findings": findings, "indicators": indicators, "categories": categories}


def _extract_auth_result(auth_string: str, protocol: str) -> Optional[str]:
    """Extract SPF/DKIM/DMARC result from Authentication-Results header."""
    pattern = rf'{protocol}\s*=\s*(\w+)'
    match = re.search(pattern, auth_string)
    return match.group(1) if match else None


def _analyze_sender_domain(parsed: Dict) -> Dict[str, Any]:
    """Analyze sender domain for suspicious characteristics."""
    findings = []
    indicators = {}
    categories = []
    score = 0.0

    sender_email = parsed.get("sender_email", "")
    if not sender_email or "@" not in sender_email:
        return {"score": 0.1, "findings": ["Invalid sender format"], "indicators": {}, "categories": []}

    domain = sender_email.split("@")[-1].lower()
    indicators["sender_domain"] = domain

    # 1. Look-alike domain detection
    lookalike_target = detect_lookalike_domain(domain)
    if lookalike_target:
        score = max(score, 0.75)
        findings.append(f"Look-alike domain detected: '{domain}' mimics '{lookalike_target}'")
        indicators["lookalike_target"] = lookalike_target
        categories.append("phishing")

    # 2. Suspicious TLD
    tld = "." + domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        score = max(score, 0.5)
        findings.append(f"Suspicious TLD detected: {tld}")
        indicators["suspicious_tld"] = tld
        categories.append("phishing")

    # 3. Free email provider (suspicious for corporate communications)
    if domain in FREE_EMAIL_PROVIDERS:
        score = max(score, 0.3)
        findings.append(f"Email from free provider: {domain} (unusual for business communication)")
        indicators["free_email_provider"] = domain

    # 4. Sender display name vs domain mismatch (impersonation)
    display_name = parsed.get("sender_display_name", "") or ""
    if display_name:
        name_lower = display_name.lower()
        # Check if display name mentions a legit company but domain doesn't match
        for legit_domain in HIGH_VALUE_DOMAINS:
            company = legit_domain.split(".")[0]
            if company in name_lower and company not in domain:
                score = max(score, 0.7)
                findings.append(
                    f"Impersonation suspected: display name '{display_name}' claims to be "
                    f"'{company}' but domain is '{domain}'"
                )
                categories.append("phishing")
                indicators["impersonation_target"] = company
                break

    # 5. Reply-To domain mismatch
    reply_to = parsed.get("reply_to", "")
    if reply_to and "@" in reply_to:
        reply_domain = reply_to.split("@")[-1].lower()
        if reply_domain != domain:
            score = max(score, 0.45)
            findings.append(f"Reply-To domain differs from sender: {reply_domain} ≠ {domain}")
            indicators["reply_to_domain_mismatch"] = {
                "sender_domain": domain,
                "reply_to_domain": reply_domain
            }
            categories.append("phishing")

    # 6. DNS lookup for sender domain
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=3)
        indicators["has_mx_record"] = True
        indicators["mx_records"] = [str(r.exchange) for r in mx_records]
    except (dns.exception.DNSException, Exception):
        score = max(score, 0.25)
        findings.append(f"No MX records found for sender domain: {domain}")
        indicators["has_mx_record"] = False
        categories.append("phishing")

    return {"score": score, "findings": findings, "indicators": indicators, "categories": categories}


def _analyze_header_anomalies(parsed: Dict) -> Dict[str, Any]:
    """Detect anomalies in email headers."""
    findings = []
    indicators = {}
    categories = []
    score = 0.0

    headers = parsed.get("raw_headers", {})

    # 1. Check From vs Envelope-From
    from_header = headers.get("From", "")
    return_path = headers.get("Return-Path", "")
    if from_header and return_path:
        from_email = re.search(r'[\w.+-]+@[\w.-]+', from_header)
        return_email = re.search(r'[\w.+-]+@[\w.-]+', return_path)
        if from_email and return_email:
            from_domain = from_email.group().split("@")[1].lower()
            return_domain = return_email.group().split("@")[1].lower()
            if from_domain != return_domain:
                score = max(score, 0.5)
                findings.append(f"From/Return-Path mismatch: {from_domain} ≠ {return_domain}")
                indicators["from_return_path_mismatch"] = True
                categories.append("phishing")

    # 2. Check for multiple From headers (header injection)
    from_headers = [v for k, v in headers.items() if k.lower() == "from"]
    if len(from_headers) > 1:
        score = max(score, 0.65)
        findings.append("Multiple 'From' headers detected (possible header injection)")
        categories.append("phishing")

    # 3. X-Originating-IP analysis
    orig_ip = headers.get("X-Originating-IP", headers.get("X-Forwarded-For", ""))
    if orig_ip:
        ip = re.search(r'\d+\.\d+\.\d+\.\d+', orig_ip)
        if ip:
            indicators["originating_ip"] = ip.group()
            # Check if it's a known bad range (simplified check)
            if _is_suspicious_ip(ip.group()):
                score = max(score, 0.4)
                findings.append(f"Originating IP in suspicious range: {ip.group()}")
                categories.append("phishing")

    # 4. Missing standard headers
    standard_headers = ["Date", "Message-ID"]
    missing = [h for h in standard_headers if h not in headers]
    if missing:
        score = max(score, 0.2)
        findings.append(f"Missing standard headers: {', '.join(missing)}")
        indicators["missing_headers"] = missing

    # 5. Check for HTML-only email (common in phishing)
    has_text = bool(parsed.get("body_text", "").strip())
    has_html = bool(parsed.get("body_html", "").strip())
    if has_html and not has_text:
        score = max(score, 0.15)
        findings.append("HTML-only email (no plain text alternative)")
        indicators["html_only"] = True

    return {"score": score, "findings": findings, "indicators": indicators, "categories": categories}


def _analyze_routing(parsed: Dict) -> Dict[str, Any]:
    """Analyze email routing path for anomalies."""
    findings = []
    indicators = {}
    categories = []
    score = 0.0

    received_chain = parsed.get("received_chain", [])
    if not received_chain:
        return {"score": 0.0, "findings": [], "indicators": {}, "categories": []}

    indicators["received_hop_count"] = len(received_chain)

    # Check for unusual hop count
    if len(received_chain) > 10:
        score = max(score, 0.2)
        findings.append(f"Unusual routing: {len(received_chain)} hops (possible relay abuse)")

    # Extract IPs from received headers
    ips = []
    for received in received_chain:
        ip_match = re.findall(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
        ips.extend(ip_match)

    indicators["routing_ips"] = ips

    # Check for known Tor exit nodes or VPN ranges (simplified)
    for ip in ips:
        if _is_suspicious_ip(ip):
            score = max(score, 0.45)
            findings.append(f"Suspicious IP in routing path: {ip}")
            categories.append("phishing")

    return {"score": score, "findings": findings, "indicators": indicators, "categories": categories}


def _is_suspicious_ip(ip: str) -> bool:
    """Simple heuristic check for suspicious IP ranges."""
    # Known bad IP ranges (simplified - in production use threat intelligence feeds)
    suspicious_ranges = [
        "185.220.",  # Tor exit nodes
        "194.165.",  # Bulletproof hosting
        "45.142.",   # Known spam networks
    ]
    return any(ip.startswith(r) for r in suspicious_ranges)


def _error_finding(agent_name: str, error: str) -> AgentFindingState:
    return AgentFindingState(
        agent_name=agent_name, score=0.0, confidence=0.0,
        findings=[f"Agent error: {error}"], indicators={},
        threat_categories=[], processing_time_ms=0,
    )
