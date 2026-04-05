"""
Tests for the email threat analysis pipeline.
"""
import pytest
import asyncio
from unittest.mock import patch, MagicMock
from app.agents.email_parser import parse_email_content, detect_lookalike_domain
from app.agents.text_agent import run_text_analysis_agent, _run_heuristics
from app.agents.metadata_agent import run_metadata_agent
from app.agents.enrichment_agent import run_enrichment_agent, _detect_aitm, _detect_lotl
from app.agents.decision_agent import run_decision_agent, _calculate_weighted_score, _determine_verdict


def make_state(email_dict=None, raw_email=None):
    """Create a minimal analysis state for testing."""
    import uuid
    import time
    return {
        "analysis_id": str(uuid.uuid4()),
        "raw_email": raw_email,
        "email_dict": email_dict,
        "source": "test",
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


class TestEmailParser:

    def test_parse_basic_email_dict(self):
        """Test parsing a basic email dictionary."""
        email_dict = {
            "subject": "Test Email",
            "sender": "test@example.com",
            "recipients": ["user@company.com"],
            "body_text": "Hello, this is a test email.",
            "headers": {},
        }
        state = make_state(email_dict=email_dict)
        result = parse_email_content(state)

        assert result["parsed_email"] is not None
        assert result["parsed_email"]["subject"] == "Test Email"
        assert result["parsed_email"]["sender_email"] == "test@example.com"

    def test_parse_email_extracts_urls(self):
        """Test that URLs are extracted from email body."""
        email_dict = {
            "subject": "Check this link",
            "sender": "sender@test.com",
            "body_text": "Click here: https://evil.phish.com/login",
        }
        state = make_state(email_dict=email_dict)
        result = parse_email_content(state)

        assert "https://evil.phish.com/login" in result["parsed_email"]["urls"]

    def test_lookalike_domain_detection(self):
        """Test homoglyph/typosquatting detection."""
        assert detect_lookalike_domain("paypa1.com") == "paypal"
        assert detect_lookalike_domain("micros0ft.com") == "microsoft"
        assert detect_lookalike_domain("google.com") is None

    def test_parse_raw_email(self):
        """Test parsing a raw RFC 2822 email."""
        raw = """From: attacker@evil.com
To: victim@company.com
Subject: Urgent Invoice
MIME-Version: 1.0
Content-Type: text/plain

Please wire $10,000 immediately.
"""
        state = make_state(raw_email=raw)
        result = parse_email_content(state)

        assert result["parsed_email"] is not None
        assert result["parsed_email"]["sender_email"] == "attacker@evil.com"
        assert "Urgent Invoice" in result["parsed_email"]["subject"]


class TestTextAgent:

    def test_bec_email_detected(self):
        """Test BEC phishing email detection."""
        text = "Please process the wire transfer of $50,000 to the new bank account immediately. This is urgent."
        result = _run_heuristics(text, "Invoice Payment Required", {})

        assert result["score"] > 0.4
        assert "business_email_compromise" in result["threat_categories"]

    def test_clean_email_low_score(self):
        """Test that legitimate emails get low scores."""
        text = "Hi team, let's schedule the Q4 review meeting for next Tuesday at 2pm."
        result = _run_heuristics(text, "Meeting Schedule", {})

        assert result["score"] < 0.3

    def test_credential_phishing_detected(self):
        """Test credential harvesting email detection."""
        text = "Your account has been suspended. Click here to verify your identity and confirm your password."
        result = _run_heuristics(text, "Account Suspended", {})

        assert result["score"] > 0.5
        assert "phishing" in result["threat_categories"]

    def test_reply_to_mismatch_flagged(self):
        """Test that Reply-To mismatch is detected."""
        parsed = {
            "sender_email": "ceo@company.com",
            "reply_to": "attacker@evil.com",
        }
        text = "Please approve this payment request."
        result = _run_heuristics(text, "Payment Request", parsed)

        assert any("Reply-To" in f for f in result["findings"])


class TestEnrichmentAgent:

    def test_aitm_detection(self):
        """Test AiTM (Adversary-in-the-Middle) URL detection."""
        malicious_url = "https://login.microsoft.com.evil.com/oauth?returnurl=https://outlook.com"
        detected, pattern = _detect_aitm(malicious_url, "login.microsoft.com.evil.com")
        assert detected

    def test_lotl_detection_dropbox(self):
        """Test Living-off-the-Land detection via Dropbox."""
        urls = ["https://www.dropbox.com/s/abc123/salary_revision.pdf"]
        body = "Please review the attached salary revision document urgently."
        result = _detect_lotl(urls, body)
        assert result["detected"]

    def test_legitimate_url_not_flagged(self):
        """Test that legitimate URLs don't trigger false positives."""
        urls = ["https://www.google.com/search?q=weather"]
        body = "Check out the weather forecast."
        result = _detect_lotl(urls, body)
        assert not result["detected"]


class TestDecisionAgent:

    def test_weighted_scoring(self):
        """Test that weighted scoring works correctly."""
        findings = [
            {
                "agent_name": "text_analysis_agent",
                "score": 0.8,
                "confidence": 0.9,
                "findings": [],
                "indicators": {},
                "threat_categories": ["phishing"],
                "processing_time_ms": 100,
            },
            {
                "agent_name": "metadata_agent",
                "score": 0.6,
                "confidence": 0.85,
                "findings": [],
                "indicators": {},
                "threat_categories": ["phishing"],
                "processing_time_ms": 50,
            },
        ]
        score, breakdown = _calculate_weighted_score(findings)
        assert 0.0 <= score <= 1.0
        assert "text_analysis_agent" in breakdown

    def test_verdict_thresholds(self):
        """Test verdict determination based on score thresholds."""
        assert _determine_verdict(0.9, []) == "malicious"
        assert _determine_verdict(0.6, []) == "suspicious"
        assert _determine_verdict(0.3, []) == "spam"
        assert _determine_verdict(0.1, []) == "clean"

    def test_malware_category_forces_suspicious(self):
        """Test that malware category overrides low score to suspicious."""
        assert _determine_verdict(0.1, ["malware"]) == "suspicious"


class TestFullPipeline:

    def test_phishing_email_full_analysis(self):
        """End-to-end test for a phishing email."""
        email_dict = {
            "subject": "URGENT: Your account has been compromised - Verify NOW",
            "sender": "security@paypa1.com",
            "recipients": ["victim@company.com"],
            "body_text": (
                "Your PayPal account has been suspended due to suspicious activity. "
                "Click here immediately to verify your credentials: "
                "https://secure.paypa1.com/login?verify=true"
            ),
            "headers": {
                "Reply-To": "attacker@totally-evil.xyz",
                "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
            },
        }
        state = make_state(email_dict=email_dict)

        # Run through agents
        state = parse_email_content(state)
        state = run_text_analysis_agent(state)
        state = run_metadata_agent(state)
        state = run_enrichment_agent(state)

        # Mock graph agent
        from app.agents.state import AgentFindingState
        graph_finding = AgentFindingState(
            agent_name="graph_correlation_agent",
            score=0.3,
            confidence=0.5,
            findings=["Graph analysis unavailable (test mode)"],
            indicators={},
            threat_categories=[],
            processing_time_ms=1,
        )
        state["agent_findings"].append(graph_finding)

        state = run_decision_agent(state)

        # Phishing email should be flagged as suspicious or malicious
        assert state["verdict"] in ["suspicious", "malicious"]
        assert state["threat_score"] >= 0.4
        assert len(state["reasoning_trace"]) > 0

    def test_clean_email_passes(self):
        """Test that a legitimate email gets clean verdict."""
        email_dict = {
            "subject": "Team lunch on Friday",
            "sender": "colleague@company.com",
            "recipients": ["team@company.com"],
            "body_text": "Hey team, shall we do lunch on Friday at 1pm? The new Italian place?",
            "headers": {
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            },
        }
        state = make_state(email_dict=email_dict)
        state = parse_email_content(state)
        state = run_text_analysis_agent(state)
        state = run_metadata_agent(state)
        state = run_enrichment_agent(state)

        from app.agents.state import AgentFindingState
        graph_finding = AgentFindingState(
            agent_name="graph_correlation_agent",
            score=0.0,
            confidence=0.8,
            findings=["No threats found in graph"],
            indicators={},
            threat_categories=[],
            processing_time_ms=1,
        )
        state["agent_findings"].append(graph_finding)
        state = run_decision_agent(state)

        assert state["verdict"] in ["clean", "spam"]
        assert state["threat_score"] < 0.4
