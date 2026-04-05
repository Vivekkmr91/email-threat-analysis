"""
Text Analysis Agent - Analyzes email body for:
- Social engineering tactics & urgency signals
- BEC / phishing intent detection
- LLM-generated text fingerprinting  (now backed by custom ML model)
- Executive impersonation patterns
- Sentiment and linguistic anomalies

ML Integration
--------------
The agent runs THREE layers of analysis in parallel and merges scores:

  1. Heuristic (regex / rule-based)  – fast, zero dependencies
  2. LLM (GPT-4o-mini)               – deep semantic understanding
  3. Custom ML Model                  – trained phishing / LLM-detect classifier
                                        (ModelRegistry, 60-feature vector)

The final score is a weighted combination:
  25% heuristic  +  35% LLM (if available)  +  40% ML model
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


# ─── Agent Main Entry Point ───────────────────────────────────────────────────

def run_text_analysis_agent(state: EmailAnalysisState) -> EmailAnalysisState:
    """
    Text Analysis Agent node for LangGraph.
    Analyzes email text for threats using heuristics, LLM, and custom ML model.
    """
    start_time = time.time()
    log = logger.bind(analysis_id=state["analysis_id"])
    log.info("Text Analysis Agent starting")

    parsed = state.get("parsed_email")
    if not parsed:
        return {**state, "agent_findings": [_error_finding("text_analysis_agent", "No parsed email")]}

    body    = parsed.get("body_text") or ""
    subject = parsed.get("subject") or ""
    sender  = parsed.get("sender_email") or ""
    headers = parsed.get("raw_headers") or {}
    urls    = parsed.get("urls") or []
    full_text = f"Subject: {subject}\n\n{body}"

    # ── Layer 1: Heuristic analysis ──────────────────────────────────────────
    heuristic_result = _run_heuristics(full_text, subject, parsed)

    # ── Layer 2: LLM analysis (optional) ────────────────────────────────────
    llm_result: Dict[str, Any] = {}
    if settings.OPENAI_API_KEY and len(full_text.strip()) > 20:
        try:
            llm_result = _run_llm_analysis(full_text, subject, parsed)
        except Exception as e:
            log.warning("LLM text analysis failed, using heuristics + ML", error=str(e))

    # ── Layer 3: Custom ML model ─────────────────────────────────────────────
    ml_result: Dict[str, Any] = {}
    try:
        ml_result = _run_ml_analysis(subject, body, sender, headers, urls)
    except Exception as e:
        log.warning("ML model analysis failed, using heuristics only", error=str(e))

    # ── Merge all layers ─────────────────────────────────────────────────────
    combined_score = _combine_scores(heuristic_result, llm_result, ml_result)

    all_findings = (
        heuristic_result.get("findings", [])
        + llm_result.get("findings", [])
        + ml_result.get("findings", [])
    )
    all_categories = list(set(
        heuristic_result.get("threat_categories", [])
        + llm_result.get("threat_categories", [])
        + ml_result.get("threat_categories", [])
    ))
    all_indicators = {
        **heuristic_result.get("indicators", {}),
        **llm_result.get("indicators", {}),
        **ml_result.get("indicators", {}),
    }

    processing_time = int((time.time() - start_time) * 1000)

    finding = AgentFindingState(
        agent_name="text_analysis_agent",
        score=combined_score,
        confidence=_merged_confidence(heuristic_result, llm_result, ml_result),
        findings=all_findings,
        indicators=all_indicators,
        threat_categories=all_categories,
        processing_time_ms=processing_time,
    )

    log.info(
        "Text Analysis Agent complete",
        score=combined_score,
        categories=all_categories,
        time_ms=processing_time,
        ml_phishing=ml_result.get("phishing_score"),
        ml_llm=ml_result.get("llm_generated_score"),
    )

    return {
        **state,
        "agent_findings": [finding],
        "text_agent_result": {
            "score":              combined_score,
            "findings":           all_findings,
            "indicators":         all_indicators,
            "categories":         all_categories,
            "ml_phishing_score":  ml_result.get("phishing_score"),
            "ml_llm_score":       ml_result.get("llm_generated_score"),
            "ml_top_features":    ml_result.get("top_features", []),
            "ml_model_version":   ml_result.get("model_version"),
        },
    }


# ─── Layer 1: Heuristics ─────────────────────────────────────────────────────

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
        findings.append("Credential harvesting indicators detected")
        indicators["credential_patterns"] = cred_hits
        categories.append("phishing")

    # Executive impersonation
    exec_hits = [p for p in EXECUTIVE_IMPERSONATION_PATTERNS if re.search(p, text_lower)]
    if exec_hits:
        score_components.append(0.35)
        findings.append("Executive title references detected (BEC risk)")
        indicators["executive_references"] = exec_hits
        categories.append("business_email_compromise")

    # Sensitive requests
    sens_hits = [p for p in SENSITIVE_REQUEST_PATTERNS if re.search(p, text_lower)]
    if sens_hits:
        score_components.append(0.55)
        findings.append("Suspicious sensitive request patterns detected")
        indicators["sensitive_patterns"] = sens_hits
        categories.append("business_email_compromise")

    # Reply-To mismatch
    sender    = parsed.get("sender_email", "")
    reply_to  = parsed.get("reply_to")
    if reply_to and sender and reply_to.lower() != sender.lower():
        score_components.append(0.4)
        findings.append(f"Reply-To mismatch: sender={sender}, reply_to={reply_to}")
        indicators["reply_to_mismatch"] = {"sender": sender, "reply_to": reply_to}
        categories.append("phishing")

    # Heuristic LLM-generated check
    if _check_llm_generated(text):
        score_components.append(0.3)
        findings.append("Text exhibits characteristics of LLM-generated content (heuristic)")
        indicators["possible_llm_generated_heuristic"] = True
        categories.append("llm_generated_phishing")

    # Calculate final score
    if not score_components:
        final_score = 0.05
        categories.append("clean")
    else:
        final_score = max(score_components)
        final_score = min(final_score + (len(score_components) - 1) * 0.05, 0.95)

    return {
        "score":            final_score,
        "confidence":       0.75,
        "findings":         findings,
        "indicators":       indicators,
        "threat_categories": list(set(categories)),
    }


def _check_llm_generated(text: str) -> bool:
    """Heuristic check for LLM-generated phishing text."""
    if len(text) < 100:
        return False
    sentences = re.split(r'[.!?]+', text)
    if not sentences:
        return False
    lengths = [len(s.split()) for s in sentences if len(s.strip()) > 5]
    if len(lengths) < 3:
        return False
    avg      = sum(lengths) / len(lengths)
    variance = sum((l - avg) ** 2 for l in lengths) / len(lengths)
    has_typos = bool(re.search(r'\b\w{1,2}\b', text.lower()))
    return variance < 8 and not has_typos and avg > 8


# ─── Layer 2: LLM (GPT) ──────────────────────────────────────────────────────

def _run_llm_analysis(text: str, subject: str, parsed: Dict) -> Dict[str, Any]:
    """Use OpenAI LLM to analyze email for sophisticated threats."""
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
        truncated = text[:3000]
        response  = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"Analyze this email:\n\n{truncated}")
        ])

        import json
        content    = response.content
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            return {
                "score":      float(result.get("threat_score", 0.0)),
                "confidence": float(result.get("confidence", 0.8)),
                "findings":   result.get("findings", []),
                "indicators": {
                    "llm_generated":       result.get("is_llm_generated", False),
                    "social_engineering":  result.get("social_engineering_tactics", []),
                    "explanation":         result.get("explanation", ""),
                },
                "threat_categories": result.get("threat_categories", []),
            }
    except Exception as e:
        logger.warning("LLM analysis JSON parse failed", error=str(e))

    return {}


# ─── Layer 3: Custom ML Model ─────────────────────────────────────────────────

def _run_ml_analysis(
    subject:  str,
    body:     str,
    sender:   str,
    headers:  Dict,
    urls:     List[str],
) -> Dict[str, Any]:
    """
    Run the custom ML phishing / LLM-generation classifier.
    Returns a findings dict compatible with the rest of the agent pipeline.
    """
    # Lazy import to avoid circular dependencies at module load time
    from app.ml.phishing_classifier import get_registry

    registry   = get_registry()
    prediction = registry.predict(
        subject=subject,
        body=body,
        sender=sender,
        headers=headers,
        urls=urls,
    )

    findings:   List[str] = []
    indicators: Dict      = {
        "ml_phishing_score":     prediction.phishing_score,
        "ml_llm_score":          prediction.llm_generated_score,
        "ml_is_phishing":        prediction.is_phishing,
        "ml_is_llm_generated":   prediction.is_llm_generated,
        "ml_model_version":      prediction.model_version,
        "ml_inference_time_ms":  prediction.inference_time_ms,
        "ml_top_features":       prediction.top_features[:5],
    }
    categories: List[str] = []

    # --- Phishing verdict ---
    if prediction.phishing_score >= 0.8:
        findings.append(
            f"ML model: HIGH phishing probability ({prediction.phishing_score:.1%})"
        )
        categories.append("phishing")
    elif prediction.phishing_score >= 0.5:
        findings.append(
            f"ML model: Moderate phishing probability ({prediction.phishing_score:.1%})"
        )
        categories.append("phishing")

    # --- LLM-generation verdict ---
    if prediction.is_llm_generated:
        findings.append(
            f"ML model: High probability of LLM-generated text "
            f"({prediction.llm_generated_score:.1%})"
        )
        categories.append("llm_generated_phishing")

        # Explain which features drove this
        top_llm_features = [
            f for f in prediction.top_features
            if f["feature_name"].startswith("llm_")
        ][:3]
        if top_llm_features:
            feat_desc = ", ".join(
                f"{f['feature_name'].replace('llm_', '')} ({f['importance']:.2f})"
                for f in top_llm_features
            )
            findings.append(f"LLM generation indicators: {feat_desc}")

    # --- Explainability: top contributing features ---
    if prediction.top_features:
        top3 = prediction.top_features[:3]
        feat_summary = "; ".join(
            f"{f['feature_name']}={f['feature_value']:.2f} (Δ={f['importance']:.2f})"
            for f in top3
        )
        findings.append(f"ML top features: {feat_summary}")

    # Convert ML phishing score to standard 0-1 threat score
    ml_score = prediction.phishing_score

    return {
        "score":             ml_score,
        "confidence":        0.82,    # ML models trained confidence
        "findings":          findings,
        "indicators":        indicators,
        "threat_categories": list(set(categories)),
        # Passthrough for text_agent_result
        "phishing_score":        prediction.phishing_score,
        "llm_generated_score":   prediction.llm_generated_score,
        "top_features":          prediction.top_features,
        "model_version":         prediction.model_version,
    }


# ─── Score Combination ────────────────────────────────────────────────────────

def _combine_scores(
    heuristic: Dict,
    llm:       Dict,
    ml:        Dict,
) -> float:
    """
    Weighted combination of heuristic, LLM, and ML scores.

    Weights:
      - Heuristic : 25%
      - LLM       : 35%  (only if available)
      - ML model  : 40%

    If LLM is unavailable, remaining weight redistributes:
      - Heuristic : 40%
      - ML model  : 60%
    """
    h_score = heuristic.get("score", 0.0)
    l_score = llm.get("score",       0.0)
    m_score = ml.get("score",        0.0)

    has_llm = bool(llm)

    if has_llm:
        combined = h_score * 0.25 + l_score * 0.35 + m_score * 0.40
    else:
        combined = h_score * 0.40 + m_score * 0.60

    return round(min(max(combined, 0.0), 1.0), 4)


def _merged_confidence(
    heuristic: Dict,
    llm:       Dict,
    ml:        Dict,
) -> float:
    """Average confidence across available layers."""
    confs = [heuristic.get("confidence", 0.75)]
    if llm:
        confs.append(llm.get("confidence", 0.8))
    confs.append(ml.get("confidence", 0.82))
    return round(sum(confs) / len(confs), 3)


# ─── Error Helper ─────────────────────────────────────────────────────────────

def _error_finding(agent_name: str, error: str) -> AgentFindingState:
    return AgentFindingState(
        agent_name="text_analysis_agent",
        score=0.0,
        confidence=0.0,
        findings=[f"Agent error: {error}"],
        indicators={},
        threat_categories=[],
        processing_time_ms=0,
    )
