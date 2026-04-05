"""
Aggregator/Decision Agent - Multi-criteria decision analysis (MCDA):
- Weighted scoring from all agent findings
- Final verdict determination (Clean / Spam / Suspicious / Malicious)
- Explainability report generation (Reasoning Trace)
- Automated response recommendations
- SOAR/Webhook trigger on high-confidence threats
"""
import time
import json
import asyncio
from typing import Dict, Any, List, Optional
import httpx
import structlog

from app.agents.state import EmailAnalysisState, AgentFindingState
from app.core.config import settings

logger = structlog.get_logger(__name__)

# ─── Agent Weights (MCDA) ────────────────────────────────────────────────────
# Based on historical accuracy and reliability of each agent
AGENT_WEIGHTS = {
    "text_analysis_agent": 0.25,
    "metadata_agent": 0.30,
    "enrichment_agent": 0.30,
    "graph_correlation_agent": 0.15,
}

# ─── Verdict Thresholds ──────────────────────────────────────────────────────
VERDICT_THRESHOLDS = {
    "malicious": 0.75,
    "suspicious": 0.45,
    "spam": 0.25,
    "clean": 0.0,
}

# ─── Category-based verdict boosts ──────────────────────────────────────────
HIGH_SEVERITY_CATEGORIES = {
    "malware": 0.20,
    "adversary_in_the_middle": 0.15,
    "quishing": 0.10,
    "business_email_compromise": 0.10,
    "llm_generated_phishing": 0.08,
}


def run_decision_agent(state: EmailAnalysisState) -> EmailAnalysisState:
    """
    Final Aggregator/Decision Agent.
    Aggregates all agent findings and produces final verdict + explainability report.
    """
    start_time = time.time()
    log = logger.bind(analysis_id=state["analysis_id"])
    log.info("Decision Agent starting")

    findings = state.get("agent_findings", [])
    parsed = state.get("parsed_email", {}) or {}

    # 1. Aggregate weighted scores
    weighted_score, agent_score_breakdown = _calculate_weighted_score(findings)

    # 2. Apply category-based boosts
    all_categories = _collect_all_categories(findings)
    category_boost = _calculate_category_boost(all_categories)
    final_score = min(weighted_score + category_boost, 1.0)

    # 3. Determine verdict
    verdict = _determine_verdict(final_score, all_categories)

    # 4. Generate reasoning trace
    reasoning_trace, reasoning_steps = _generate_reasoning_trace(
        findings, final_score, verdict, parsed, agent_score_breakdown, category_boost
    )

    # 5. Generate recommended actions
    recommended_actions = _generate_recommendations(verdict, all_categories, final_score)

    # 6. Trigger automated response if needed
    if verdict == "malicious" and final_score >= settings.HIGH_RISK_THRESHOLD:
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(
                _trigger_automated_response(state["analysis_id"], verdict, final_score, parsed)
            )
            loop.close()
        except Exception as e:
            log.warning("Automated response trigger failed", error=str(e))

    total_time = int((time.time() - start_time) * 1000)
    start_ts = state.get("start_time", time.time())
    total_analysis_time = int((time.time() - start_ts) * 1000)

    log.info(
        "Decision Agent complete",
        verdict=verdict,
        score=final_score,
        categories=all_categories,
        total_ms=total_analysis_time
    )

    return {
        **state,
        "verdict": verdict,
        "threat_score": final_score,
        "threat_categories": list(set(all_categories)),
        "reasoning_trace": reasoning_trace,
        "reasoning_steps": reasoning_steps,
        "recommended_actions": recommended_actions,
        "analysis_duration_ms": total_analysis_time,
    }


def _calculate_weighted_score(findings: List[AgentFindingState]) -> tuple:
    """Calculate weighted average score from all agent findings."""
    total_weight = 0.0
    weighted_sum = 0.0
    breakdown = {}

    for finding in findings:
        agent_name = finding.get("agent_name", "unknown")
        score = finding.get("score", 0.0)
        weight = AGENT_WEIGHTS.get(agent_name, 0.1)

        weighted_sum += score * weight
        total_weight += weight
        breakdown[agent_name] = {
            "score": score,
            "weight": weight,
            "weighted_contribution": score * weight,
            "confidence": finding.get("confidence", 0.5),
        }

    if total_weight == 0:
        return 0.0, breakdown

    return weighted_sum / total_weight, breakdown


def _collect_all_categories(findings: List[AgentFindingState]) -> List[str]:
    """Collect all threat categories from agent findings."""
    categories = []
    for finding in findings:
        categories.extend(finding.get("threat_categories", []))
    return list(set(categories))


def _calculate_category_boost(categories: List[str]) -> float:
    """Calculate score boost based on high-severity threat categories."""
    boost = 0.0
    for category in categories:
        boost += HIGH_SEVERITY_CATEGORIES.get(category, 0.0)
    return min(boost, 0.25)  # Cap total boost


def _determine_verdict(score: float, categories: List[str]) -> str:
    """Determine final verdict based on score and categories."""
    # Override: if malware category detected, always at least suspicious
    if "malware" in categories and score < VERDICT_THRESHOLDS["suspicious"]:
        score = VERDICT_THRESHOLDS["suspicious"]

    if score >= VERDICT_THRESHOLDS["malicious"]:
        return "malicious"
    elif score >= VERDICT_THRESHOLDS["suspicious"]:
        return "suspicious"
    elif score >= VERDICT_THRESHOLDS["spam"]:
        return "spam"
    else:
        return "clean"


def _generate_reasoning_trace(
    findings: List[AgentFindingState],
    final_score: float,
    verdict: str,
    parsed: Dict,
    score_breakdown: Dict,
    category_boost: float,
) -> tuple:
    """Generate human-readable explainability report."""
    subject = parsed.get("subject", "N/A")
    sender = parsed.get("sender_email", "N/A")

    # Build narrative reasoning trace
    trace_parts = [
        f"**Email Analysis Report**\n",
        f"Subject: \"{subject}\" | From: {sender}\n",
        f"Final Verdict: **{verdict.upper()}** (Score: {final_score:.2%})\n\n",
        "**Agent Findings:**\n",
    ]

    reasoning_steps = []

    for finding in findings:
        agent_name = finding.get("agent_name", "unknown")
        score = finding.get("score", 0.0)
        agent_findings = finding.get("findings", [])
        confidence = finding.get("confidence", 0.5)
        categories = finding.get("threat_categories", [])

        # Add to trace
        verdict_emoji = "🔴" if score >= 0.7 else "🟡" if score >= 0.4 else "🟢"
        agent_display = agent_name.replace("_", " ").title()
        trace_parts.append(
            f"\n{verdict_emoji} **{agent_display}** "
            f"(Score: {score:.2%}, Confidence: {confidence:.0%})\n"
        )

        if agent_findings:
            for f in agent_findings[:5]:  # Top 5 findings per agent
                trace_parts.append(f"  • {f}\n")
        else:
            trace_parts.append("  • No significant threats detected\n")

        # Add to structured steps
        breakdown = score_breakdown.get(agent_name, {})
        reasoning_steps.append({
            "step": len(reasoning_steps) + 1,
            "agent": agent_name,
            "score": score,
            "confidence": confidence,
            "weighted_score": breakdown.get("weighted_contribution", 0),
            "categories": categories,
            "key_findings": agent_findings[:5],
        })

    # Score calculation explanation
    trace_parts.append(f"\n**Score Calculation:**\n")
    for agent_name, breakdown in score_breakdown.items():
        trace_parts.append(
            f"  • {agent_name.replace('_', ' ').title()}: "
            f"{breakdown['score']:.2%} × {breakdown['weight']:.0%} weight "
            f"= {breakdown['weighted_contribution']:.3f}\n"
        )
    if category_boost > 0:
        trace_parts.append(f"  • Category boost: +{category_boost:.2%}\n")
    trace_parts.append(f"  • **Final Score: {final_score:.2%}**\n")

    # Verdict explanation
    trace_parts.append(f"\n**Verdict: {verdict.upper()}**\n")
    verdict_explanations = {
        "malicious": "Multiple high-confidence threat indicators detected. Immediate action recommended.",
        "suspicious": "Several threat indicators detected. Manual review recommended.",
        "spam": "Email exhibits spam characteristics but limited malicious indicators.",
        "clean": "No significant threat indicators detected. Email appears legitimate.",
    }
    trace_parts.append(verdict_explanations.get(verdict, ""))

    # Add decision step
    reasoning_steps.append({
        "step": len(reasoning_steps) + 1,
        "agent": "decision_agent",
        "score": final_score,
        "confidence": 0.9,
        "weighted_score": final_score,
        "categories": _collect_all_categories(findings),
        "key_findings": [f"Final verdict: {verdict.upper()} with score {final_score:.2%}"],
    })

    return "".join(trace_parts), reasoning_steps


def _generate_recommendations(
    verdict: str, categories: List[str], score: float
) -> List[str]:
    """Generate actionable recommendations based on verdict."""
    recommendations = []

    if verdict == "malicious":
        recommendations.extend([
            "QUARANTINE: Move email to quarantine immediately",
            "BLOCK: Block sender address and domain",
            "ALERT: Notify security team immediately",
            "INVESTIGATE: Check if other users received similar emails",
        ])
        if "business_email_compromise" in categories:
            recommendations.append(
                "BEC RESPONSE: Contact finance team to verify any requested payments"
            )
        if "malware" in categories:
            recommendations.append(
                "MALWARE RESPONSE: Do not open attachments; scan endpoints if opened"
            )
        if "adversary_in_the_middle" in categories:
            recommendations.append(
                "AiTM RESPONSE: Reset credentials if user clicked links; review session logs"
            )

    elif verdict == "suspicious":
        recommendations.extend([
            "REVIEW: Flag for security analyst review",
            "WARN: Add warning banner to email",
            "MONITOR: Watch for similar emails from same sender",
        ])

    elif verdict == "spam":
        recommendations.extend([
            "SPAM: Move to spam/junk folder",
            "UNSUBSCRIBE: Check for unsubscribe option if from mailing list",
        ])

    else:
        recommendations.append("CLEAN: No action required")

    return recommendations


async def _trigger_automated_response(
    analysis_id: str, verdict: str, score: float, parsed: Dict
) -> None:
    """Trigger SOAR/Webhook automated response for high-confidence threats."""
    if not settings.SOAR_WEBHOOK_URL:
        logger.debug("No SOAR webhook configured, skipping automated response")
        return

    payload = {
        "event": "email_threat_detected",
        "analysis_id": analysis_id,
        "verdict": verdict,
        "threat_score": score,
        "sender": parsed.get("sender_email"),
        "subject": parsed.get("subject"),
        "recommended_action": "quarantine",
        "timestamp": time.time(),
    }

    headers = {}
    if settings.SOAR_API_KEY:
        headers["Authorization"] = f"Bearer {settings.SOAR_API_KEY}"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(
                settings.SOAR_WEBHOOK_URL,
                json=payload,
                headers=headers
            )
            logger.info(
                "SOAR webhook triggered",
                status_code=response.status_code,
                analysis_id=analysis_id
            )
        except Exception as e:
            logger.error("SOAR webhook failed", error=str(e))
