"""
LangGraph Orchestrator - Multi-agent pipeline coordinator.
Manages state, agent routing, parallel execution, and retries.
"""
import time
import uuid
import asyncio
from typing import Dict, Any, Optional
import structlog

from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from app.agents.state import EmailAnalysisState
from app.agents.email_parser import parse_email_content
from app.agents.text_agent import run_text_analysis_agent
from app.agents.metadata_agent import run_metadata_agent
from app.agents.enrichment_agent import run_enrichment_agent
from app.agents.graph_agent import run_graph_agent
from app.agents.decision_agent import run_decision_agent

logger = structlog.get_logger(__name__)



async def _run_parallel_agents(state: EmailAnalysisState) -> EmailAnalysisState:
    """
    Run Text, Metadata, and Enrichment agents in parallel using threads.
    Each agent independently analyzes the email and appends to agent_findings.
    """
    log = logger.bind(analysis_id=state["analysis_id"])
    log.info("Starting parallel agent execution")

    results = await asyncio.gather(
        asyncio.to_thread(run_text_analysis_agent, state),
        asyncio.to_thread(run_metadata_agent, state),
        run_enrichment_agent(state),
    )

    # Merge all agent findings and intermediate results
    merged_state = {**state}
    all_findings = list(state.get("agent_findings", []))
    all_errors = list(state.get("errors", []))

    for result in results:
        all_findings.extend(result.get("agent_findings", []))
        all_errors.extend(result.get("errors", []))

        # Merge intermediate results
        for key in ["text_agent_result", "metadata_agent_result",
                    "enrichment_agent_result", "url_analyses",
                    "attachment_analyses", "spf_result", "dkim_result", "dmarc_result"]:
            if result.get(key) is not None:
                merged_state[key] = result[key]

    merged_state["agent_findings"] = all_findings
    merged_state["errors"] = all_errors

    log.info(f"Parallel agents complete", finding_count=len(all_findings))
    return merged_state


def _run_graph_agent_node(state: EmailAnalysisState) -> EmailAnalysisState:
    """Run graph correlation agent (sequential - after parallel agents)."""
    return run_graph_agent(state)


def build_analysis_graph() -> StateGraph:
    """
    Build the LangGraph StateGraph for email threat analysis.
    
    Pipeline:
    1. Parse Email
    2. Parallel: [Text Agent] + [Metadata Agent] + [Enrichment Agent]
    3. Graph Correlation Agent (uses results from step 2)
    4. Decision Agent (aggregates all findings)
    """
    workflow = StateGraph(EmailAnalysisState)

    # Add nodes
    workflow.add_node("parse_email", parse_email_content)
    workflow.add_node("parallel_analysis", _run_parallel_agents)
    workflow.add_node("graph_analysis", _run_graph_agent_node)
    workflow.add_node("decision", run_decision_agent)

    # Add edges
    workflow.set_entry_point("parse_email")
    workflow.add_edge("parse_email", "parallel_analysis")
    workflow.add_edge("parallel_analysis", "graph_analysis")
    workflow.add_edge("graph_analysis", "decision")
    workflow.add_edge("decision", END)

    return workflow.compile()


# ─── Compiled Graph (singleton) ─────────────────────────────────────────────
_analysis_graph = None


def get_analysis_graph():
    """Get or create the compiled analysis graph."""
    global _analysis_graph
    if _analysis_graph is None:
        _analysis_graph = build_analysis_graph()
        logger.info("LangGraph analysis pipeline compiled")
    return _analysis_graph


async def analyze_email(
    raw_email: Optional[str] = None,
    email_dict: Optional[Dict[str, Any]] = None,
    source: str = "api",
    analysis_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main entry point for email threat analysis.
    
    Args:
        raw_email: Raw RFC 2822 email string
        email_dict: Structured email dict from API
        source: Email source identifier
        analysis_id: Optional pre-assigned analysis ID
        
    Returns:
        Complete analysis result dict
    """
    if not analysis_id:
        analysis_id = str(uuid.uuid4())

    log = logger.bind(analysis_id=analysis_id)
    log.info("Starting email analysis", source=source)

    # Initialize state
    initial_state: EmailAnalysisState = {
        "analysis_id": analysis_id,
        "raw_email": raw_email,
        "email_dict": email_dict,
        "source": source,
        "start_time": time.time(),
        "parsed_email": None,
        "agent_findings": [],
        "text_agent_result": None,
        "metadata_agent_result": None,
        "enrichment_agent_result": None,
        "graph_agent_result": None,
        "url_analyses": [],
        "attachment_analyses": [],
        "header_analysis": None,
        "spf_result": None,
        "dkim_result": None,
        "dmarc_result": None,
        "verdict": None,
        "threat_score": 0.0,
        "threat_categories": [],
        "reasoning_trace": None,
        "reasoning_steps": [],
        "recommended_actions": [],
        "analysis_duration_ms": 0,
        "errors": [],
    }

    # Run the graph
    graph = get_analysis_graph()

    final_state = await graph.ainvoke(
        initial_state,
        config=RunnableConfig(recursion_limit=10)
    )

    log.info(
        "Analysis complete",
        verdict=final_state.get("verdict"),
        score=final_state.get("threat_score"),
        duration_ms=final_state.get("analysis_duration_ms"),
    )

    return final_state
