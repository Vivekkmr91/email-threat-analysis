"""
Text Analysis Agent - Analyzes email body for:
- Social engineering tactics & urgency signals
- BEC / phishing intent detection
- LLM-generated text fingerprinting
- Executive impersonation patterns
- Sentiment and linguistic anomalies
"""
import time
import re
from typing import Dict, Any, List, Optional
import structlog
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage

from app.agents.state import EmailAnalysisState, AgentFindingState
from app.core.config import settings

logger = structlog.get_logger(__name__)

# ─── Heuristic Patterns ──────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r'\burgent\b', r'\bimmediately\b', r'\basap\b', r'\baction required\b',
    r'\btime.sensitive\b', r'\bdeadline\b', r'\btoday\b', r'\bright now\b',
    r'\bhours?\b.*\bexpire', r'\bfinal notice\b',
]

FINANCIAL_FRAUD_PATTERNS = [
    r'\bwire transfer\b', r'\btransfer\b.*\b\$[\d,]+', r'\bnew.*(bank|account).*detail',
    r'\bpayment.*instruct', r'\binvoice.*overdue', r'\bprocess.*payment',
    r'\bbank.*routing.*number', r'\bift\b', r'\bswift\b.*\bcode\b',
    r'\bchange.*banking\b', r'\bupdated.*account\b',
]

CREDENTIAL_HARVEST_PATTERNS = [
    r'\bclick here\b.*\bverif', r'\bconfirm.*password\b', r'\bsecure.*login\b',
    r'\bsign.in.*required\b', r'\baccount.*suspend', r'\bverif.*identity\b',
    r'\bupdate.*credentials\b', r'\benter.*username\b',
]

EXECUTIVE_IMPERSONATION_PATTERNS = [
    r'\bceo\b', r'\bchief executive\b', r'\bpresident\b', r'\bcfo\b',
    r'\bchief financial\b', r'\bdirector\b', r'\bvp\b.*\bfinance\b',
    r'\bmanaging director\b', r'\bvice president\b',
]

SENSITIVE_REQUEST_PATTERNS = [
    r'\bgift card', r'\biTunes\b', r'\bamazon.*gift\b', r'\bGoogle Play\b',
    r'\bkeep.*confidential\b', r'\bdo not tell\b', r'\bsecret\b',
    r'\bpersonal favor\b', r'\boff.the.record\b',
]


def run_text_analysis_agent(state: EmailAnalysisState) -> EmailAnalysisState:
    """
    Text Analysis Agent node for LangGraph.
    Analyzes email text for threats using both heuristics and LLM.
    """
    start_time = time.time()
    log = logger.bind(analysis_id=state["analysis_id"])
    log.info("Text Analysis Agent starting")

    parsed = state.get("parsed_email")
    if not parsed:
        return {**state, "agent_findings": [_error_finding("text_analysis_agent", "No parsed email")]}

    body = parsed.get("body_text") or ""
    subject = parsed.get("subject") or ""
    full_text = f"Subject: {subject}\n\n{body}"

    # Run heuristic analysis
    heuristic_result = _run_heuristics(full_text, subject, parsed)

    # Run LLM analysis if available
    llm_result = {}
    if settings.OPENAI_API_KEY and len(full_text.strip()) > 20:
        try:
            llm_result = _run_llm_analysis(full_text, subject, parsed)
        except Exception as e:
            log.warning("LLM text analysis failed, using heuristics only", error=str(e))

    # Combine results
    combined_score = _combine_scores(heuristic_result, llm_result)
    all_findings = heuristic_result.get("findings", []) + llm_result.get("findings", [])
    all_categories = list(set(
        heuristic_result.get("threat_categories", []) + llm_result.get("threat_categories", [])
    ))
    all_indicators = {**heuristic_result.get("indicators", {}), **llm_result.get("indicators", {})}

    processing_time = int((time.time() - start_time) * 1000)

    finding = AgentFindingState(
        agent_name="text_analysis_agent",
        score=combined_score,
        confidence=heuristic_result.get("confidence", 0.7),
        findings=all_findings,
        indicators=all_indicators,
        threat_categories=all_categories,
        processing_time_ms=processing_time,
    )

    log.info("Text Analysis Agent complete",
             score=combined_score, categories=all_categories, time_ms=processing_time)

    return {
        **state,
        "agent_findings": [finding],
        "text_agent_result": {
            "score": combined_score,
            "findings": all_findings,
            "indicators": all_indicators,
            "categories": all_categories,
        }
    }


def _run_heuristics(text: str, subject: str, parsed: Dict) -> Dict[str, Any]:
    """Run regex-based heuristic analysis."""
    text_lower = text.lower()
    findings = []
    indicators = {}
    categories = []
    score_components = []

    # Urgency detection
    urgency_hits = [p for p in URGENCY_PATTERNS if re.search(p, text_lower)]
    if urgency_hits:
        count = len(urgency_hits)
        urgency_score = min(0.3 + (count * 0.05), 0.5)
        score_components.append(urgency_score)
        findings.append(f"Urgency language detected: {count} pattern(s) matched")
        indicators["urgency_patterns"] = urgency_hits
        categories.append("phishing")

    # Financial fraud patterns
    fin_hits = [p for p in FINANCIAL_FRAUD_PATTERNS if re.search(p, text_lower)]
    if fin_hits:
        count = len(fin_hits)
        fin_score = min(0.4 + (count * 0.08), 0.75)
        score_components.append(fin_score)
        findings.append(f"Financial fraud indicators: {count} pattern(s) matched")
        indicators["financial_patterns"] = fin_hits
        categories.append("business_email_compromise")

    # Credential harvesting
    cred_hits = [p for p in CREDENTIAL_HARVEST_PATTERNS if re.search(p, text_lower)]
    if cred_hits:
        score_components.append(0.6)
        findings.append(f"Credential harvesting indicators detected")
        indicators["credential_patterns"] = cred_hits
        categories.append("phishing")

    # Executive impersonation
    exec_hits = [p for p in EXECUTIVE_IMPERSONATION_PATTERNS if re.search(p, text_lower)]
    if exec_hits:
        score_components.append(0.35)
        findings.append(f"Executive title references detected (BEC risk)")
        indicators["executive_references"] = exec_hits
        categories.append("business_email_compromise")

    # Sensitive requests
    sens_hits = [p for p in SENSITIVE_REQUEST_PATTERNS if re.search(p, text_lower)]
    if sens_hits:
        score_components.append(0.55)
        findings.append(f"Suspicious sensitive request patterns detected")
        indicators["sensitive_patterns"] = sens_hits
        categories.append("business_email_compromise")

    # Reply-To mismatch
    sender = parsed.get("sender_email", "")
    reply_to = parsed.get("reply_to")
    if reply_to and sender and reply_to.lower() != sender.lower():
        score_components.append(0.4)
        findings.append(f"Reply-To mismatch: sender={sender}, reply_to={reply_to}")
        indicators["reply_to_mismatch"] = {"sender": sender, "reply_to": reply_to}
        categories.append("phishing")

    # Check for LLM-generated text markers (too perfect, no informal language)
    if _check_llm_generated(text):
        score_components.append(0.3)
        findings.append("Text exhibits characteristics of LLM-generated content")
        indicators["possible_llm_generated"] = True
        categories.append("llm_generated_phishing")

    # Calculate final score
    if not score_components:
        final_score = 0.05
        categories.append("clean")
    else:
        final_score = max(score_components)
        final_score = min(final_score + (len(score_components) - 1) * 0.05, 0.95)

    return {
        "score": final_score,
        "confidence": 0.75,
        "findings": findings,
        "indicators": indicators,
        "threat_categories": list(set(categories)),
    }


def _check_llm_generated(text: str) -> bool:
    """Heuristic check for LLM-generated phishing text."""
    if len(text) < 100:
        return False
    sentences = re.split(r'[.!?]+', text)
    if not sentences:
        return False
    # Very uniform sentence lengths can indicate LLM generation
    lengths = [len(s.split()) for s in sentences if len(s.strip()) > 5]
    if len(lengths) < 3:
        return False
    avg = sum(lengths) / len(lengths)
    variance = sum((l - avg) ** 2 for l in lengths) / len(lengths)
    # Low variance + no typos + formal language = possible LLM
    has_typos = bool(re.search(r'\b\w{1,2}\b', text.lower()))  # very short words as proxy
    return variance < 8 and not has_typos and avg > 8


def _run_llm_analysis(text: str, subject: str, parsed: Dict) -> Dict[str, Any]:
    """Use LLM to analyze email for sophisticated threats."""
    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        temperature=settings.OPENAI_TEMPERATURE,
        api_key=settings.OPENAI_API_KEY,
        max_tokens=800,
    )

    system_prompt = """You are a cybersecurity expert specializing in email threat analysis.
Analyze the provided email for:
1. Social engineering tactics (urgency, authority, fear, scarcity)
2. Business Email Compromise (BEC) indicators
3. Phishing intent (credential harvesting, fake login pages)
4. LLM-generated phishing characteristics (overly formal, grammatically perfect, no personal details)
5. Executive impersonation patterns

Respond in JSON with this structure:
{
  "threat_score": 0.0-1.0,
  "confidence": 0.0-1.0,
  "is_llm_generated": true/false,
  "social_engineering_tactics": ["list of tactics found"],
  "threat_categories": ["phishing", "business_email_compromise", etc.],
  "findings": ["specific finding 1", "finding 2"],
  "explanation": "brief explanation"
}

Be conservative - only flag clear threats. Return threat_score=0.0 for legitimate emails."""

    try:
        truncated_text = text[:3000]  # Limit context
        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"Analyze this email:\n\n{truncated_text}")
        ])

        import json
        content = response.content
        # Extract JSON from response
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            return {
                "score": float(result.get("threat_score", 0.0)),
                "confidence": float(result.get("confidence", 0.8)),
                "findings": result.get("findings", []),
                "indicators": {
                    "llm_generated": result.get("is_llm_generated", False),
                    "social_engineering": result.get("social_engineering_tactics", []),
                    "explanation": result.get("explanation", ""),
                },
                "threat_categories": result.get("threat_categories", []),
            }
    except Exception as e:
        logger.warning("LLM analysis JSON parse failed", error=str(e))

    return {}


def _combine_scores(heuristic: Dict, llm: Dict) -> float:
    """Combine heuristic and LLM scores with weighted average."""
    h_score = heuristic.get("score", 0.0)
    l_score = llm.get("score", 0.0)

    if l_score == 0.0:
        return h_score

    # Weight: 40% heuristic, 60% LLM
    return (h_score * 0.4) + (l_score * 0.6)


def _error_finding(agent_name: str, error: str) -> AgentFindingState:
    return AgentFindingState(
        agent_name=agent_name,
        score=0.0,
        confidence=0.0,
        findings=[f"Agent error: {error}"],
        indicators={},
        threat_categories=[],
        processing_time_ms=0,
    )
