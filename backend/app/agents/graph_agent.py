"""
Graph Correlation Agent - Neo4j-powered relationship analysis:
- Sender/domain/IP historical reputation
- Campaign detection and correlation
- Behavioral baseline deviation
- Cross-entity threat correlation
- Attack pattern recognition
"""
import time
import re
from typing import Dict, Any, List, Optional
import structlog

from app.agents.state import EmailAnalysisState, AgentFindingState
from app.core.database import neo4j_session
from app.core.config import settings

logger = structlog.get_logger(__name__)


def run_graph_agent(state: EmailAnalysisState) -> EmailAnalysisState:
    """Graph Correlation Agent node for LangGraph."""
    import asyncio
    start_time = time.time()
    log = logger.bind(analysis_id=state["analysis_id"])
    log.info("Graph Agent starting")

    parsed = state.get("parsed_email")
    if not parsed:
        return {**state, "agent_findings": [_error_finding("graph_correlation_agent", "No parsed email")]}

    # Run async Neo4j operations
    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(_async_graph_analysis(state, parsed))
        loop.close()
    except Exception as e:
        log.error("Graph agent async execution failed", error=str(e))
        result = _fallback_graph_analysis(parsed)

    processing_time = int((time.time() - start_time) * 1000)
    result["processing_time_ms"] = processing_time

    finding = AgentFindingState(
        agent_name="graph_correlation_agent",
        score=result.get("score", 0.0),
        confidence=result.get("confidence", 0.75),
        findings=result.get("findings", []),
        indicators=result.get("indicators", {}),
        threat_categories=result.get("categories", []),
        processing_time_ms=processing_time,
    )

    log.info("Graph Agent complete", score=result.get("score", 0.0), time_ms=processing_time)

    return {
        **state,
        "agent_findings": [finding],
        "graph_agent_result": {
            "score": result.get("score", 0.0),
            "findings": result.get("findings", []),
            "indicators": result.get("indicators", {}),
            "categories": result.get("categories", []),
        }
    }


async def _async_graph_analysis(state: EmailAnalysisState, parsed: Dict) -> Dict[str, Any]:
    """Async Neo4j graph analysis."""
    findings = []
    indicators = {}
    categories = []
    score_components = []

    sender_email = parsed.get("sender_email", "")
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    urls = parsed.get("urls", [])
    recipient_emails = parsed.get("recipient_emails", [])

    try:
        async with neo4j_session() as session:
            # 1. Check sender reputation in graph
            if sender_email:
                reputation = await _get_entity_reputation(session, sender_email, "EmailAddress")
                if reputation:
                    indicators["sender_reputation"] = reputation
                    if reputation.get("threat_score", 0) > 0.5:
                        score_components.append(reputation["threat_score"])
                        findings.append(
                            f"Known threat actor: Sender '{sender_email}' "
                            f"has threat score {reputation['threat_score']:.2f}"
                        )
                        categories.append("phishing")

            # 2. Check sender domain in graph
            if sender_domain:
                domain_rep = await _get_entity_reputation(session, sender_domain, "Domain")
                if domain_rep:
                    indicators["domain_reputation"] = domain_rep
                    if domain_rep.get("threat_score", 0) > 0.5:
                        score_components.append(domain_rep["threat_score"])
                        findings.append(
                            f"Malicious domain: '{sender_domain}' "
                            f"appears in {domain_rep.get('campaigns', 0)} known campaigns"
                        )
                        categories.append("phishing")
                    if domain_rep.get("age_days", 999) < 30:
                        score_components.append(0.45)
                        findings.append(
                            f"New domain: '{sender_domain}' registered only "
                            f"{domain_rep['age_days']} days ago"
                        )

            # 3. Check URLs in graph
            for url in urls[:5]:  # Check first 5 URLs
                url_domain = _extract_domain(url)
                if url_domain:
                    url_rep = await _get_entity_reputation(session, url_domain, "Domain")
                    if url_rep and url_rep.get("threat_score", 0) > 0.5:
                        score_components.append(url_rep["threat_score"])
                        findings.append(f"URL domain '{url_domain}' found in threat graph")
                        categories.append("phishing")

            # 4. Campaign correlation
            campaign = await _check_campaign_correlation(session, sender_email, sender_domain, urls)
            if campaign:
                score_components.append(0.7)
                findings.append(
                    f"Campaign correlation: Matches known campaign '{campaign['name']}' "
                    f"with {campaign.get('email_count', 0)} related emails"
                )
                indicators["campaign"] = campaign
                categories.append(campaign.get("category", "phishing"))

            # 5. Behavioral baseline (sender-recipient pattern)
            if sender_email and recipient_emails:
                baseline = await _check_behavioral_baseline(
                    session, sender_email, recipient_emails[0] if recipient_emails else ""
                )
                if baseline:
                    indicators["behavioral_baseline"] = baseline
                    if not baseline.get("known_relationship", False):
                        score_components.append(0.3)
                        findings.append(
                            f"No historical communication found between "
                            f"'{sender_email}' and recipient (first contact)"
                        )

            # 6. Store analysis data in graph
            await _store_analysis_in_graph(
                session, state["analysis_id"], parsed,
                score_components, categories
            )

    except Exception as e:
        logger.error("Neo4j query failed", error=str(e))
        findings.append(f"Graph analysis limited (DB unavailable)")
        return _fallback_graph_analysis(parsed)

    # Calculate final score
    if not score_components:
        final_score = 0.05
    else:
        final_score = max(score_components)
        if len(score_components) >= 2:
            final_score = min(final_score + 0.05 * (len(score_components) - 1), 0.95)

    return {
        "score": final_score,
        "confidence": 0.80,
        "findings": findings,
        "indicators": indicators,
        "categories": list(set(categories)),
    }


async def _get_entity_reputation(session, entity_id: str, entity_type: str) -> Optional[Dict]:
    """Query Neo4j for entity reputation."""
    query = f"""
    MATCH (n:{entity_type} {{{'address' if entity_type != 'Domain' else 'name'}: $entity_id}})
    OPTIONAL MATCH (n)-[:PART_OF]->(c:Campaign)
    RETURN n.threat_score as threat_score,
           n.last_seen as last_seen,
           n.age_days as age_days,
           count(c) as campaigns
    """
    result = await session.run(query, entity_id=entity_id)
    record = await result.single()
    if record and record["threat_score"] is not None:
        return {
            "threat_score": float(record["threat_score"] or 0),
            "last_seen": str(record["last_seen"] or ""),
            "age_days": int(record["age_days"] or 999),
            "campaigns": int(record["campaigns"] or 0),
        }
    return None


async def _check_campaign_correlation(
    session, sender_email: str, sender_domain: str, urls: List[str]
) -> Optional[Dict]:
    """Check if current email matches known attack campaigns."""
    url_domains = [_extract_domain(u) for u in urls[:5] if _extract_domain(u)]

    query = """
    MATCH (c:Campaign)
    WHERE c.sender_domain = $sender_domain
       OR any(d IN $url_domains WHERE c.url_domain = d)
    RETURN c.id as id, c.name as name, c.category as category,
           c.email_count as email_count, c.first_seen as first_seen
    ORDER BY c.email_count DESC
    LIMIT 1
    """
    result = await session.run(query, sender_domain=sender_domain, url_domains=url_domains)
    record = await result.single()
    if record:
        return {
            "id": record["id"],
            "name": record["name"] or "Unknown Campaign",
            "category": record["category"] or "phishing",
            "email_count": record["email_count"] or 0,
            "first_seen": str(record["first_seen"] or ""),
        }
    return None


async def _check_behavioral_baseline(
    session, sender_email: str, recipient_email: str
) -> Optional[Dict]:
    """Check historical communication pattern between sender and recipient."""
    if not sender_email or not recipient_email:
        return None

    query = """
    MATCH (s:EmailAddress {address: $sender})
    MATCH (r:EmailAddress {address: $recipient})
    OPTIONAL MATCH (s)-[comm:COMMUNICATED_WITH]->(r)
    RETURN comm.count as count, comm.last_date as last_date
    """
    result = await session.run(query, sender=sender_email, recipient=recipient_email)
    record = await result.single()
    if record:
        count = record["count"] or 0
        return {
            "known_relationship": count > 0,
            "communication_count": count,
            "last_communication": str(record["last_date"] or ""),
        }
    return {"known_relationship": False, "communication_count": 0}


async def _store_analysis_in_graph(
    session, analysis_id: str, parsed: Dict,
    threat_scores: List[float], categories: List[str]
) -> None:
    """Store analysis results as graph nodes/relationships."""
    sender_email = parsed.get("sender_email", "")
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    threat_score = max(threat_scores) if threat_scores else 0.0

    # Create/update sender node
    if sender_email:
        await session.run("""
            MERGE (e:EmailAddress {address: $address})
            ON CREATE SET e.first_seen = datetime(), e.threat_score = $score
            ON MATCH SET e.last_seen = datetime(),
                         e.threat_score = CASE WHEN $score > e.threat_score
                                          THEN $score ELSE e.threat_score END,
                         e.analysis_count = coalesce(e.analysis_count, 0) + 1
        """, address=sender_email, score=threat_score)

    # Create/update domain node
    if sender_domain:
        await session.run("""
            MERGE (d:Domain {name: $domain})
            ON CREATE SET d.first_seen = datetime(), d.threat_score = $score
            ON MATCH SET d.last_seen = datetime(),
                         d.threat_score = CASE WHEN $score > d.threat_score
                                          THEN $score ELSE d.threat_score END
        """, domain=sender_domain, score=threat_score)

    # Link email address to domain
    if sender_email and sender_domain:
        await session.run("""
            MATCH (e:EmailAddress {address: $email})
            MATCH (d:Domain {name: $domain})
            MERGE (e)-[:BELONGS_TO]->(d)
        """, email=sender_email, domain=sender_domain)

    # Create URL nodes
    for url in parsed.get("urls", [])[:10]:
        url_domain = _extract_domain(url)
        if url_domain:
            await session.run("""
                MERGE (u:URL {url: $url})
                ON CREATE SET u.first_seen = datetime(), u.domain = $domain
                ON MATCH SET u.last_seen = datetime()
            """, url=url[:500], domain=url_domain)


def _fallback_graph_analysis(parsed: Dict) -> Dict[str, Any]:
    """Fallback analysis when Neo4j is unavailable."""
    return {
        "score": 0.1,
        "confidence": 0.3,
        "findings": ["Graph analysis unavailable (using fallback heuristics)"],
        "indicators": {"neo4j_available": False},
        "categories": [],
    }


def _extract_domain(url: str) -> Optional[str]:
    """Safely extract domain from URL."""
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.lower().strip("www.")
    except Exception:
        return None


def _error_finding(agent_name: str, error: str) -> AgentFindingState:
    return AgentFindingState(
        agent_name=agent_name, score=0.0, confidence=0.0,
        findings=[f"Agent error: {error}"], indicators={},
        threat_categories=[], processing_time_ms=0,
    )
