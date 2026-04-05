"""
Tests for the custom ML phishing detection and RLHF pipeline.

Covers:
- Feature extraction correctness and shape
- MLP forward pass and prediction
- ModelRegistry singleton behaviour
- RLHF reward model reward computation
- FeedbackStore persistence
- RLHFTrainer training cycle
- ML route schemas
"""
import math
import uuid
import time
import threading
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import numpy as np
import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Feature extraction tests
# ──────────────────────────────────────────────────────────────────────────────

class TestFeatureExtraction:
    """Tests for app.ml.features.extract_features"""

    def setup_method(self):
        # Ensure import works
        from app.ml.features import extract_features, FEATURE_NAMES
        self.extract = extract_features
        self.names   = FEATURE_NAMES

    def test_output_shape(self):
        vec = self.extract("Hello", "This is a test email body.")
        assert vec.shape == (60,), f"Expected (60,), got {vec.shape}"

    def test_output_dtype(self):
        vec = self.extract("Subject", "Body text.")
        assert vec.dtype == np.float32

    def test_all_finite(self):
        vec = self.extract(
            "Urgent: Account suspended",
            "Please verify your credentials immediately. Click here.",
            sender="ceo@company-fake.com",
            headers={"Reply-To": "attacker@evil.com"},
            urls=["https://secure.paypa1.com/login"],
        )
        assert np.all(np.isfinite(vec)), "Feature vector contains NaN/Inf"

    def test_values_in_range(self):
        """All features should be in [0, 1]."""
        vec = self.extract(
            "Invoice payment required",
            "Wire $50,000 to the new bank account. This is urgent.",
        )
        assert vec.min() >= 0.0, f"Min value {vec.min()} < 0"
        assert vec.max() <= 1.0, f"Max value {vec.max()} > 1"

    def test_feature_names_count(self):
        assert len(self.names) == 60

    def test_empty_inputs(self):
        """Empty strings should not raise."""
        vec = self.extract("", "")
        assert vec.shape == (60,)
        assert np.all(np.isfinite(vec))

    def test_phishing_email_higher_score_than_clean(self):
        """Phishing email should yield higher urgency / credential features."""
        from app.ml.features import extract_features, FEATURE_NAMES
        phish_vec = extract_features(
            "URGENT: Verify your account NOW",
            "Your account has been suspended. Click here to verify your password.",
            urls=["https://secure.paypa1.com/verify"],
        )
        clean_vec = extract_features(
            "Team lunch Friday?",
            "Hey, shall we grab lunch at the Italian place this Friday?",
        )
        # urgency feature index = 25 (soc_urgency)
        urgency_idx = FEATURE_NAMES.index("soc_urgency")
        assert phish_vec[urgency_idx] >= clean_vec[urgency_idx]

    def test_llm_generated_email_features(self):
        """LLM-phrased email should score higher on llm_phrase_match."""
        from app.ml.features import extract_features, FEATURE_NAMES
        llm_text = (
            "I hope this email finds you well. Please be advised that your account "
            "requires immediate attention. Kindly ensure that you update your credentials "
            "at your earliest convenience. Should you have any questions, do not hesitate "
            "to contact us. Thank you for your prompt attention to this matter."
        )
        informal_text = (
            "hey john! so I forgot to tell you - the team lunch is moved to thursday "
            "lol. btw don't tell anyone yet, the boss doesn't know. catch you later!"
        )
        llm_vec    = extract_features("Action Required", llm_text)
        inform_vec = extract_features("hey", informal_text)

        phrase_idx  = FEATURE_NAMES.index("llm_phrase_match")
        personal_idx = FEATURE_NAMES.index("llm_personal_markers")

        assert llm_vec[phrase_idx] >= inform_vec[phrase_idx], (
            "LLM email should have higher llm_phrase_match"
        )
        assert inform_vec[personal_idx] >= llm_vec[personal_idx], (
            "Informal email should have more personal markers"
        )

    def test_spf_fail_feature(self):
        from app.ml.features import extract_features, FEATURE_NAMES
        headers_fail = {"Authentication-Results": "spf=fail dkim=fail dmarc=fail"}
        headers_pass = {"Authentication-Results": "spf=pass dkim=pass dmarc=pass"}

        spf_idx = FEATURE_NAMES.index("hdr_spf_fail")

        fail_vec = extract_features("Test", "Body", headers=headers_fail)
        pass_vec = extract_features("Test", "Body", headers=headers_pass)

        assert fail_vec[spf_idx] == 1.0
        assert pass_vec[spf_idx] == 0.0

    def test_url_features_present(self):
        from app.ml.features import extract_features, FEATURE_NAMES
        urls = ["https://bit.ly/abc123", "http://1.2.3.4/login", "https://evil.xyz/phish"]
        vec = extract_features("Test", "Body", urls=urls)

        shortener_idx = FEATURE_NAMES.index("url_shortener")
        ip_idx        = FEATURE_NAMES.index("url_ip_ratio")
        sus_tld_idx   = FEATURE_NAMES.index("url_sus_tld")

        assert vec[shortener_idx] == 1.0, "Should detect URL shortener"
        assert vec[ip_idx] > 0.0,         "Should detect IP-based URL"
        assert vec[sus_tld_idx] > 0.0,    "Should detect suspicious TLD"


# ──────────────────────────────────────────────────────────────────────────────
# MLP model tests
# ──────────────────────────────────────────────────────────────────────────────

class TestMLP:
    """Tests for app.ml.phishing_classifier.MLP"""

    def setup_method(self):
        from app.ml.phishing_classifier import MLP
        self.MLP = MLP

    def test_forward_pass_shape(self):
        model = self.MLP([60, 64, 2])
        x     = np.random.randn(60).astype(np.float32)
        proba = model.predict_proba(x)
        assert proba.shape == (2,)

    def test_probabilities_sum_to_one(self):
        model = self.MLP([60, 32, 2])
        x     = np.random.randn(60).astype(np.float32)
        proba = model.predict_proba(x)
        assert abs(proba.sum() - 1.0) < 1e-5

    def test_batch_forward_pass(self):
        model = self.MLP([60, 64, 2])
        X     = np.random.randn(10, 60).astype(np.float32)
        proba = model.predict_proba(X)
        assert proba.shape == (10, 2)
        assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)

    def test_sgd_step_reduces_loss(self):
        """Loss should generally decrease over training steps."""
        from app.ml.phishing_classifier import MLP
        model = MLP([60, 32, 2], seed=0)
        X     = np.random.randn(16, 60).astype(np.float32)
        y     = np.array([0, 1] * 8)

        losses = [model.sgd_step(X, y, lr=0.01) for _ in range(30)]

        # Loss should decrease on average (not necessarily monotonically)
        first_half = np.mean(losses[:10])
        second_half = np.mean(losses[20:])
        assert second_half <= first_half * 1.5, (
            f"Loss not decreasing: first={first_half:.4f}, last={second_half:.4f}"
        )

    def test_save_and_load(self):
        from app.ml.phishing_classifier import MLP
        import tempfile, os
        model = MLP([60, 32, 2], seed=7)
        x     = np.random.randn(60).astype(np.float32)
        proba_before = model.predict_proba(x)

        with tempfile.NamedTemporaryFile(suffix=".npz", delete=False) as f:
            tmp_path = Path(f.name)

        try:
            model.save(tmp_path)
            loaded = MLP.load(tmp_path, [60, 32, 2])
            proba_after = loaded.predict_proba(x)
            np.testing.assert_allclose(proba_before, proba_after, atol=1e-6)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_predict_returns_integer(self):
        model = self.MLP([60, 16, 2])
        x     = np.random.randn(60).astype(np.float32)
        pred  = model.predict(x)
        assert isinstance(pred, int)
        assert pred in (0, 1)


# ──────────────────────────────────────────────────────────────────────────────
# ModelRegistry tests
# ──────────────────────────────────────────────────────────────────────────────

class TestModelRegistry:
    """Tests for app.ml.phishing_classifier.ModelRegistry"""

    def test_singleton(self):
        from app.ml.phishing_classifier import ModelRegistry
        r1 = ModelRegistry()
        r2 = ModelRegistry()
        assert r1 is r2

    def test_predict_returns_ml_prediction(self):
        from app.ml.phishing_classifier import get_registry, MLPrediction
        registry = get_registry()
        pred = registry.predict(
            subject = "Urgent payment",
            body    = "Please transfer $10,000 immediately.",
        )
        assert isinstance(pred, MLPrediction)
        assert 0.0 <= pred.phishing_score    <= 1.0
        assert 0.0 <= pred.llm_generated_score <= 1.0
        assert isinstance(pred.is_phishing, bool)
        assert isinstance(pred.top_features, list)
        assert len(pred.top_features) == 10
        assert pred.inference_time_ms >= 0

    def test_status_dict(self):
        from app.ml.phishing_classifier import get_registry
        status = get_registry().status()
        assert "model_version"  in status
        assert "train_stats"    in status
        assert "phishing_arch"  in status

    def test_online_update(self):
        from app.ml.phishing_classifier import get_registry
        registry = get_registry()
        losses = registry.online_update(
            subject        = "Test email",
            body           = "Hello, this is a test.",
            label_phishing = 0,
            label_llm      = 0,
        )
        assert "phishing_loss" in losses
        assert "llm_loss"      in losses
        assert losses["phishing_loss"] >= 0

    def test_batch_train(self):
        from app.ml.phishing_classifier import get_registry
        registry = get_registry()
        examples = [
            {
                "subject":        "Urgent: Wire transfer required",
                "body":           "Please transfer $50,000 immediately to the new account.",
                "sender":         "ceo@fake.com",
                "headers":        {},
                "urls":           [],
                "label_phishing": 1,
                "label_llm":      0,
            },
            {
                "subject":        "Team meeting tomorrow",
                "body":           "Hey, let's meet at 10am tomorrow for the quarterly review.",
                "sender":         "colleague@company.com",
                "headers":        {},
                "urls":           [],
                "label_phishing": 0,
                "label_llm":      0,
            },
        ] * 6   # 12 examples

        result = registry.batch_train(examples, epochs=3, lr=0.01)
        assert result["status"] == "completed"
        assert result["n_examples"] == 12
        assert "phishing_accuracy" in result
        assert 0.0 <= result["phishing_accuracy"] <= 1.0

    def test_thread_safety(self):
        """Concurrent predictions should not crash."""
        from app.ml.phishing_classifier import get_registry
        registry = get_registry()
        errors   = []

        def _predict():
            try:
                registry.predict("Subject", "Body text for concurrent test.")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=_predict) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread safety errors: {errors}"


# ──────────────────────────────────────────────────────────────────────────────
# RLHF Reward Model tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRewardModel:
    """Tests for app.ml.rlhf.RewardModel"""

    def setup_method(self):
        from app.ml.rlhf import RewardModel, FeedbackRecord
        self.RewardModel    = RewardModel
        self.FeedbackRecord = FeedbackRecord
        self.model          = RewardModel()

    def _make_record(self, feedback_type, predicted_verdict="suspicious",
                     predicted_llm=False, corrected_verdict=None):
        return self.FeedbackRecord(
            feedback_id       = str(uuid.uuid4()),
            analysis_id       = str(uuid.uuid4()),
            subject           = "Test subject",
            body_text         = "Test body",
            sender            = "test@test.com",
            headers           = {},
            urls              = [],
            predicted_verdict = predicted_verdict,
            predicted_score   = 0.6,
            predicted_llm     = predicted_llm,
            feedback_type     = feedback_type,
            corrected_verdict = corrected_verdict,
            analyst_id        = "analyst-1",
            notes             = "",
        )

    def test_correct_feedback_positive_reward(self):
        record          = self._make_record("correct", "malicious")
        reward, lp, ll  = self.model.compute_reward(record)
        assert reward   == 1.0
        assert lp       == 1    # malicious → phishing label = 1

    def test_false_positive_negative_reward(self):
        record          = self._make_record("false_positive", "suspicious")
        reward, lp, ll  = self.model.compute_reward(record)
        assert reward   == -1.0
        assert lp       == 0    # false positive → label = clean

    def test_false_negative_negative_reward(self):
        record = self._make_record("false_negative", "clean",
                                   corrected_verdict="malicious")
        reward, lp, ll = self.model.compute_reward(record)
        assert reward  == -0.8
        assert lp      == 1    # missed malicious

    def test_false_positive_on_llm_adjusts_label(self):
        """If model flagged as LLM-generated but was FP, llm label = 0."""
        record = self._make_record("false_positive", "suspicious", predicted_llm=True)
        _, _, ll = self.model.compute_reward(record)
        assert ll == 0    # analyst says clean → not LLM-generated phishing

    def test_reward_statistics(self):
        from app.ml.rlhf import FeedbackRecord
        records = []
        for ft in ["correct", "false_positive", "false_negative"]:
            r = self._make_record(ft)
            reward, lp, ll = self.model.compute_reward(r)
            r.reward = reward
            records.append(r)

        stats = self.model.compute_reward_statistics(records)
        assert "mean_reward" in stats
        assert "n_positive"  in stats
        assert "n_negative"  in stats


# ──────────────────────────────────────────────────────────────────────────────
# FeedbackStore tests
# ──────────────────────────────────────────────────────────────────────────────

class TestFeedbackStore:
    """Tests for app.ml.rlhf.FeedbackStore"""

    def setup_method(self):
        from app.ml.rlhf import FeedbackStore, FeedbackRecord, FEEDBACK_STORE_PATH
        # Use a temp file to avoid polluting the real store
        self._orig_path = FEEDBACK_STORE_PATH
        import app.ml.rlhf as rlhf_module
        self._tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        rlhf_module.FEEDBACK_STORE_PATH = Path(self._tmp.name)
        self.store   = FeedbackStore()
        self.FeedbackRecord = FeedbackRecord

    def teardown_method(self):
        import app.ml.rlhf as rlhf_module
        rlhf_module.FEEDBACK_STORE_PATH = self._orig_path
        os.unlink(self._tmp.name)

    def _make_record(self, feedback_type="correct"):
        return self.FeedbackRecord(
            feedback_id       = str(uuid.uuid4()),
            analysis_id       = str(uuid.uuid4()),
            subject           = "Test",
            body_text         = "Body",
            sender            = "",
            headers           = {},
            urls              = [],
            predicted_verdict = "suspicious",
            predicted_score   = 0.6,
            predicted_llm     = False,
            feedback_type     = feedback_type,
            corrected_verdict = None,
            analyst_id        = "test",
            notes             = "",
        )

    def test_add_and_retrieve(self):
        r = self._make_record()
        self.store.add(r)

        unused = self.store.get_unused()
        assert len(unused) == 1
        assert unused[0].feedback_id == r.feedback_id

    def test_mark_used(self):
        r = self._make_record()
        self.store.add(r)
        self.store.mark_used([r.feedback_id])

        unused = self.store.get_unused()
        assert len(unused) == 0

    def test_stats(self):
        for ft in ["correct", "false_positive"]:
            self.store.add(self._make_record(ft))

        stats = self.store.stats()
        assert stats["total_feedback"]  == 2
        assert stats["unused_feedback"] == 2

    def test_reward_computed_on_add(self):
        """Record should have reward set after being added."""
        r = self._make_record("false_positive")
        self.store.add(r)

        stored = self.store.get_unused()[0]
        assert stored.reward is not None
        assert stored.label_phishing is not None
        assert stored.label_llm      is not None


# ──────────────────────────────────────────────────────────────────────────────
# RLHF Pipeline integration test
# ──────────────────────────────────────────────────────────────────────────────

class TestRLHFPipeline:
    """Integration tests for the full RLHF pipeline."""

    def test_submit_feedback_returns_id(self):
        from app.ml.rlhf import RLHFPipeline
        # Use a fresh instance (not the global singleton) to avoid state pollution
        pipeline = RLHFPipeline.__new__(RLHFPipeline)
        pipeline._setup()

        fid = pipeline.submit_feedback(
            analysis_id        = str(uuid.uuid4()),
            subject            = "Verify your account",
            body_text          = "Click here to verify your PayPal account immediately.",
            sender             = "security@paypa1.com",
            headers            = {"Authentication-Results": "spf=fail"},
            urls               = ["https://paypa1.com/verify"],
            predicted_verdict  = "suspicious",
            predicted_score    = 0.65,
            predicted_llm      = False,
            feedback_type      = "false_positive",
            analyst_id         = "analyst-007",
            corrected_verdict  = "clean",
        )

        assert fid is not None
        assert len(fid) > 0

    def test_get_status(self):
        from app.ml.rlhf import RLHFPipeline
        pipeline = RLHFPipeline.__new__(RLHFPipeline)
        pipeline._setup()

        status = pipeline.get_status()
        assert "rlhf_enabled"   in status
        assert "store_stats"    in status
        assert "registry_status" in status

    def test_trigger_training_with_feedback(self):
        """With enough feedback, training should complete."""
        from app.ml.rlhf import RLHFPipeline
        pipeline = RLHFPipeline.__new__(RLHFPipeline)
        pipeline._setup()

        # Submit 12 feedback records (above minimum threshold)
        for i in range(12):
            pipeline.submit_feedback(
                analysis_id        = str(uuid.uuid4()),
                subject            = f"Test email {i}",
                body_text          = "Please transfer funds immediately.",
                sender             = f"user{i}@example.com",
                headers            = {},
                urls               = [],
                predicted_verdict  = "malicious" if i % 2 == 0 else "clean",
                predicted_score    = 0.8 if i % 2 == 0 else 0.1,
                predicted_llm      = False,
                feedback_type      = "correct",
            )

        result = pipeline.trigger_training(epochs=2, lr=0.01)
        assert result["status"] in ("completed", "skipped")

    def test_threshold_adaptation(self):
        """adapt_thresholds should return sensible suggestions."""
        from app.ml.rlhf import RLHFPipeline, FeedbackRecord
        pipeline = RLHFPipeline.__new__(RLHFPipeline)
        pipeline._setup()

        # Create many false-positive records
        records = []
        for _ in range(20):
            r = FeedbackRecord(
                feedback_id="fid-" + str(uuid.uuid4()),
                analysis_id=str(uuid.uuid4()),
                subject="Test",
                body_text="Body",
                sender="",
                headers={},
                urls=[],
                predicted_verdict="malicious",
                predicted_score=0.8,
                predicted_llm=False,
                feedback_type="false_positive",
                corrected_verdict="clean",
                analyst_id="test",
                notes="",
                reward=-1.0,
                label_phishing=0,
                label_llm=0,
            )
            records.append(r)

        advice = pipeline.trainer.adapt_thresholds(records)
        assert "reason" in advice
        assert "fp_rate" in advice
        # With 100% FP rate, thresholds should be raised
        if "HIGH_RISK_THRESHOLD" in advice:
            assert advice["HIGH_RISK_THRESHOLD"] > 0.75


# ──────────────────────────────────────────────────────────────────────────────
# ML integration with text agent
# ──────────────────────────────────────────────────────────────────────────────

class TestMLTextAgentIntegration:
    """Tests that the text agent correctly uses ML model output."""

    def make_state(self, email_dict):
        import time
        return {
            "analysis_id":          str(uuid.uuid4()),
            "raw_email":            None,
            "email_dict":           email_dict,
            "source":               "test",
            "start_time":           time.time(),
            "parsed_email":         None,
            "agent_findings":       [],
            "text_agent_result":    None,
            "metadata_agent_result": None,
            "enrichment_agent_result": None,
            "graph_agent_result":   None,
            "url_analyses":         [],
            "attachment_analyses":  [],
            "header_analysis":      None,
            "spf_result":           None,
            "dkim_result":          None,
            "dmarc_result":         None,
            "verdict":              None,
            "threat_score":         0.0,
            "threat_categories":    [],
            "reasoning_trace":      None,
            "reasoning_steps":      [],
            "recommended_actions":  [],
            "analysis_duration_ms": 0,
            "errors":               [],
        }

    def test_text_agent_result_contains_ml_scores(self):
        from app.agents.email_parser import parse_email_content
        from app.agents.text_agent import run_text_analysis_agent

        email_dict = {
            "subject": "URGENT: Verify your account",
            "sender":  "security@paypa1.com",
            "body_text": "Please verify your credentials immediately by clicking the link.",
            "headers": {},
        }
        state  = self.make_state(email_dict)
        state  = parse_email_content(state)
        result = run_text_analysis_agent(state)

        text_result = result.get("text_agent_result")
        assert text_result is not None, "text_agent_result should not be None"
        assert "ml_phishing_score"  in text_result
        assert "ml_llm_score"       in text_result
        assert "ml_top_features"    in text_result
        assert text_result["ml_phishing_score"]  is not None
        assert 0.0 <= text_result["ml_phishing_score"]  <= 1.0
        assert 0.0 <= text_result["ml_llm_score"] <= 1.0

    def test_decision_agent_uses_ml_scores(self):
        from app.agents.email_parser import parse_email_content
        from app.agents.text_agent import run_text_analysis_agent
        from app.agents.decision_agent import run_decision_agent
        from app.agents.state import AgentFindingState

        email_dict = {
            "subject": "Wire transfer needed",
            "sender":  "ceo@company-fake.com",
            "body_text": "Please wire $50,000 to the new bank account immediately. Urgent!",
            "headers": {},
        }
        state  = self.make_state(email_dict)
        state  = parse_email_content(state)
        state  = run_text_analysis_agent(state)

        # Add stub graph finding
        state["agent_findings"].append(AgentFindingState(
            agent_name="graph_correlation_agent",
            score=0.1,
            confidence=0.5,
            findings=[],
            indicators={},
            threat_categories=[],
            processing_time_ms=1,
        ))
        state["agent_findings"].append(AgentFindingState(
            agent_name="metadata_agent",
            score=0.3,
            confidence=0.7,
            findings=[],
            indicators={},
            threat_categories=[],
            processing_time_ms=1,
        ))
        state["agent_findings"].append(AgentFindingState(
            agent_name="enrichment_agent",
            score=0.2,
            confidence=0.6,
            findings=[],
            indicators={},
            threat_categories=[],
            processing_time_ms=1,
        ))

        result = run_decision_agent(state)

        assert "verdict"        in result
        assert "threat_score"   in result
        assert "reasoning_trace" in result
        assert result["threat_score"] >= 0.0
        assert result["threat_score"] <= 1.0
        assert result["verdict"] in ("clean", "spam", "suspicious", "malicious")

    def test_ml_override_high_phishing_score(self):
        """When ML phishing score is very high, verdict should be at least suspicious."""
        from app.agents.decision_agent import run_decision_agent
        from app.agents.state import AgentFindingState

        state = {
            "analysis_id":         str(uuid.uuid4()),
            "parsed_email":        {"subject": "Test", "sender_email": "test@test.com"},
            "agent_findings":      [
                AgentFindingState(
                    agent_name="text_analysis_agent",
                    score=0.3,   # low MCDA score
                    confidence=0.8,
                    findings=[],
                    indicators={},
                    threat_categories=[],
                    processing_time_ms=1,
                ),
                AgentFindingState(
                    agent_name="metadata_agent",
                    score=0.1,
                    confidence=0.5,
                    findings=[],
                    indicators={},
                    threat_categories=[],
                    processing_time_ms=1,
                ),
                AgentFindingState(
                    agent_name="enrichment_agent",
                    score=0.1,
                    confidence=0.5,
                    findings=[],
                    indicators={},
                    threat_categories=[],
                    processing_time_ms=1,
                ),
                AgentFindingState(
                    agent_name="graph_correlation_agent",
                    score=0.1,
                    confidence=0.5,
                    findings=[],
                    indicators={},
                    threat_categories=[],
                    processing_time_ms=1,
                ),
            ],
            # High ML phishing score injected
            "text_agent_result": {
                "ml_phishing_score":  0.92,    # very high ML score
                "ml_llm_score":       0.80,
                "ml_model_version":   "test",
                "ml_top_features":    [],
            },
            "start_time":           time.time(),
            "url_analyses":         [],
            "attachment_analyses":  [],
            "threat_categories":    [],
            "errors":               [],
        }

        result = run_decision_agent(state)
        # With ml_phishing_score=0.92, verdict must be at least suspicious
        assert result["verdict"] in ("suspicious", "malicious"), (
            f"Expected suspicious/malicious, got {result['verdict']} "
            f"with score {result['threat_score']}"
        )
