"""
LangGraph state definition - the shared state passed between all agents.
"""
from typing import TypedDict, Optional, List, Dict, Any, Annotated
from datetime import datetime
import operator


class AgentFindingState(TypedDict):
    agent_name: str
    score: float
    confidence: float
    findings: List[str]
    indicators: Dict[str, Any]
    threat_categories: List[str]
    processing_time_ms: int


class ParsedEmail(TypedDict):
    message_id: Optional[str]
    subject: Optional[str]
    sender_email: Optional[str]
    sender_display_name: Optional[str]
    recipient_emails: List[str]
    reply_to: Optional[str]
    raw_headers: Dict[str, str]
    body_text: Optional[str]
    body_html: Optional[str]
    urls: List[str]
    attachment_filenames: List[str]
    attachment_data: List[Dict[str, Any]]  # [{filename, content_bytes, mime_type}]
    received_chain: List[str]
    date_sent: Optional[str]


class EmailAnalysisState(TypedDict):
    """
    Complete shared state for the multi-agent email analysis pipeline.
    Uses LangGraph's reducer for accumulating findings from parallel agents.
    """
    # Input
    analysis_id: str
    raw_email: Optional[str]
    email_dict: Optional[Dict[str, Any]]
    source: str
    start_time: float

    # Parsed email components
    parsed_email: Optional[ParsedEmail]

    # Agent findings (accumulated via list append)
    agent_findings: Annotated[List[AgentFindingState], operator.add]

    # Individual agent outputs
    text_agent_result: Optional[Dict[str, Any]]
    metadata_agent_result: Optional[Dict[str, Any]]
    enrichment_agent_result: Optional[Dict[str, Any]]
    graph_agent_result: Optional[Dict[str, Any]]

    # Intermediate data shared between agents
    url_analyses: List[Dict[str, Any]]
    attachment_analyses: List[Dict[str, Any]]
    header_analysis: Optional[Dict[str, Any]]
    spf_result: Optional[str]
    dkim_result: Optional[str]
    dmarc_result: Optional[str]

    # Final decision
    verdict: Optional[str]
    threat_score: float
    threat_categories: List[str]
    reasoning_trace: Optional[str]
    reasoning_steps: List[Dict[str, Any]]
    recommended_actions: List[str]
    analysis_duration_ms: int

    # Error tracking
    errors: Annotated[List[str], operator.add]
