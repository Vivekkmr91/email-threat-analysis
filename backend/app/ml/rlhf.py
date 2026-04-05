"""
RLHF (Reinforcement Learning from Human Feedback) Pipeline
===========================================================

This module implements the complete RLHF loop for the email threat analysis
system.  The flow is:

  Analyst submits feedback
        │
        ▼
  FeedbackStore.add()          ← persists feedback into an in-memory / DB queue
        │
        ▼
  RewardModel.compute_reward() ← converts human feedback into a scalar reward
        │
        ▼
  RLHFTrainer.collect_and_train()
        │ (triggered async / by Celery task)
        ▼
  ModelRegistry.batch_train()  ← fine-tunes phishing & LLM-detection models
        │
        ▼
  ModelRegistry.update_weights() ← atomically swaps live model weights

Key design decisions:
- No external dependency (no TF/PyTorch) – pure NumPy for portability
- Reward signal is computed from analyst feedback + historical accuracy
- PPO-style clipping is approximated by bounded LR updates
- All training is done asynchronously (Celery or background thread)
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import structlog

from app.ml.features import extract_features
from app.ml.phishing_classifier import ModelRegistry, PHISHING_ARCH, LLM_DETECT_ARCH

logger = structlog.get_logger(__name__)

FEEDBACK_STORE_PATH = Path(os.getenv("ML_MODEL_DIR", "/tmp/email_threat_ml")) / "feedback_store.json"
MIN_EXAMPLES_FOR_TRAINING = int(os.getenv("RLHF_MIN_EXAMPLES", "10"))
TRAINING_INTERVAL_HOURS   = float(os.getenv("RLHF_TRAIN_INTERVAL_HOURS", "6"))


# ──────────────────────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FeedbackRecord:
    """One analyst feedback event tied to a single email analysis."""
    feedback_id:    str
    analysis_id:    str
    # Email content (needed to extract features for retraining)
    subject:        str
    body_text:      str
    sender:         str
    headers:        Dict
    urls:           List[str]
    # Original model prediction
    predicted_verdict:  str          # clean / spam / suspicious / malicious
    predicted_score:    float
    predicted_llm:      bool
    # Human correction
    feedback_type:  str   # "correct" | "false_positive" | "false_negative"
    corrected_verdict: Optional[str]  # if false_positive/negative, what it should be
    analyst_id:     str
    notes:          str
    timestamp:      float = field(default_factory=time.time)
    # Derived labels (set after computing reward)
    label_phishing: Optional[int] = None  # 0 = clean, 1 = phishing
    label_llm:      Optional[int] = None  # 0 = human, 1 = llm-generated
    reward:         Optional[float] = None

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "FeedbackRecord":
        return cls(**d)


# ──────────────────────────────────────────────────────────────────────────────
# Reward Model
# ──────────────────────────────────────────────────────────────────────────────

class RewardModel:
    """
    Converts analyst feedback into a scalar reward signal and ground-truth
    labels for supervised fine-tuning.

    Reward values:
      +1.0  → prediction was correct           (analyst says "correct")
      -1.0  → prediction was false positive     (flagged as threat but clean)
      -0.8  → prediction was false negative     (missed a real threat)
      +0.5  → borderline / uncertain feedback
    """

    VERDICT_TO_PHISHING_LABEL: Dict[str, int] = {
        "clean":      0,
        "spam":       0,
        "suspicious": 1,
        "malicious":  1,
    }

    def compute_reward(self, record: FeedbackRecord) -> Tuple[float, int, int]:
        """
        Returns (reward, label_phishing, label_llm).
        """
        feedback = record.feedback_type

        if feedback == "correct":
            reward = 1.0
            # Use the predicted verdict as ground truth
            label_phishing = self.VERDICT_TO_PHISHING_LABEL.get(
                record.predicted_verdict, 0
            )
        elif feedback == "false_positive":
            # Model said threat, analyst says clean
            reward = -1.0
            label_phishing = 0    # ground truth = clean
        elif feedback == "false_negative":
            # Model said clean, analyst says threat
            reward = -0.8
            correct = record.corrected_verdict or "malicious"
            label_phishing = self.VERDICT_TO_PHISHING_LABEL.get(correct, 1)
        else:
            reward = 0.0
            label_phishing = self.VERDICT_TO_PHISHING_LABEL.get(
                record.predicted_verdict, 0
            )

        # LLM label: if analyst corrects a false positive and the email
        # was flagged as LLM-generated, it was NOT (since it was clean).
        if feedback == "false_positive" and record.predicted_llm:
            label_llm = 0    # model over-estimated LLM generation
        elif record.predicted_llm:
            label_llm = 1
        else:
            label_llm = 0

        return reward, label_phishing, label_llm

    def compute_reward_statistics(self, records: List[FeedbackRecord]) -> Dict:
        """Aggregate reward statistics over a batch."""
        rewards = [r.reward for r in records if r.reward is not None]
        if not rewards:
            return {}
        return {
            "mean_reward":   float(np.mean(rewards)),
            "std_reward":    float(np.std(rewards)),
            "min_reward":    float(np.min(rewards)),
            "max_reward":    float(np.max(rewards)),
            "n_positive":    sum(1 for r in rewards if r > 0),
            "n_negative":    sum(1 for r in rewards if r < 0),
            "n_neutral":     sum(1 for r in rewards if r == 0),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Feedback Store
# ──────────────────────────────────────────────────────────────────────────────

class FeedbackStore:
    """
    Thread-safe in-memory store with JSON persistence.
    Holds all analyst feedback records awaiting use in training.
    """

    def __init__(self) -> None:
        self._lock    = threading.Lock()
        self._records: List[FeedbackRecord] = []
        self._used_ids: set = set()
        self._reward_model = RewardModel()
        self._load()

    def add(self, record: FeedbackRecord) -> None:
        reward, label_p, label_l = self._reward_model.compute_reward(record)
        record.reward         = reward
        record.label_phishing = label_p
        record.label_llm      = label_l

        with self._lock:
            self._records.append(record)
            self._save()

        logger.info(
            "Feedback added to RLHF store",
            feedback_id=record.feedback_id,
            analysis_id=record.analysis_id,
            feedback_type=record.feedback_type,
            reward=reward,
        )

    def get_unused(self, limit: int = 500) -> List[FeedbackRecord]:
        """Return records not yet consumed in a training run."""
        with self._lock:
            unused = [r for r in self._records
                      if r.feedback_id not in self._used_ids]
        return unused[:limit]

    def mark_used(self, feedback_ids: List[str]) -> None:
        with self._lock:
            self._used_ids.update(feedback_ids)
            self._save()

    def stats(self) -> Dict:
        with self._lock:
            total  = len(self._records)
            unused = sum(1 for r in self._records
                         if r.feedback_id not in self._used_ids)
        return {
            "total_feedback":   total,
            "unused_feedback":  unused,
            "used_feedback":    total - unused,
        }

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save(self) -> None:
        try:
            FEEDBACK_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "records":   [r.to_dict() for r in self._records],
                "used_ids":  list(self._used_ids),
            }
            FEEDBACK_STORE_PATH.write_text(json.dumps(payload, indent=2))
        except Exception as e:
            logger.warning("FeedbackStore save failed", error=str(e))

    def _load(self) -> None:
        if not FEEDBACK_STORE_PATH.exists():
            return
        try:
            payload = json.loads(FEEDBACK_STORE_PATH.read_text())
            self._records  = [FeedbackRecord.from_dict(r) for r in payload.get("records", [])]
            self._used_ids = set(payload.get("used_ids", []))
            logger.info("FeedbackStore loaded", n_records=len(self._records))
        except Exception as e:
            logger.warning("FeedbackStore load failed", error=str(e))


# ──────────────────────────────────────────────────────────────────────────────
# RLHF Trainer
# ──────────────────────────────────────────────────────────────────────────────

class RLHFTrainer:
    """
    Orchestrates the RLHF training loop.

    Steps
    -----
    1. Pull unused feedback records from FeedbackStore
    2. Convert each record to a training example (features + labels)
    3. Weight examples by absolute reward (high reward = more important)
    4. Call ModelRegistry.batch_train()
    5. Mark feedback records as used
    6. Log training report
    """

    def __init__(
        self,
        feedback_store: FeedbackStore,
        registry:       ModelRegistry,
    ) -> None:
        self._store    = feedback_store
        self._registry = registry
        self._reward_model = RewardModel()
        self._last_train_ts: Optional[float] = None

    def should_train(self) -> bool:
        """Return True if training conditions are met."""
        stats = self._store.stats()
        if stats["unused_feedback"] < MIN_EXAMPLES_FOR_TRAINING:
            return False
        if self._last_train_ts is not None:
            elapsed_h = (time.time() - self._last_train_ts) / 3600
            if elapsed_h < TRAINING_INTERVAL_HOURS:
                return False
        return True

    def run_training_cycle(
        self,
        epochs:     int = 15,
        lr:         float = 5e-4,
        batch_size: int = 32,
    ) -> Dict:
        """
        Execute one complete RLHF training cycle.
        Safe to call from Celery worker or background thread.
        """
        records = self._store.get_unused()
        if not records:
            return {"status": "skipped", "reason": "no_unused_feedback"}

        logger.info("RLHF training cycle starting", n_records=len(records))

        # Build training examples (reward-weighted)
        examples = []
        for r in records:
            if r.label_phishing is None or r.label_llm is None:
                continue
            examples.append({
                "subject":        r.subject,
                "body":           r.body_text,
                "sender":         r.sender,
                "headers":        r.headers,
                "urls":           r.urls,
                "label_phishing": r.label_phishing,
                "label_llm":      r.label_llm,
                "weight":         abs(r.reward or 1.0),
            })

        if not examples:
            return {"status": "skipped", "reason": "no_valid_examples"}

        # Weight examples: replicate high-reward examples up to 3×
        weighted_examples = []
        for ex in examples:
            reps = max(1, round(ex["weight"] * 2))
            weighted_examples.extend([ex] * reps)

        # Run batch training
        train_result = self._registry.batch_train(
            examples=weighted_examples,
            epochs=epochs,
            lr=lr,
            batch_size=batch_size,
        )

        # Compute reward statistics
        reward_stats = self._reward_model.compute_reward_statistics(records)

        # Mark as used
        self._store.mark_used([r.feedback_id for r in records])
        self._last_train_ts = time.time()

        # Bump model version
        new_version = f"rlhf-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        self._registry.update_weights(version=new_version)

        result = {
            "status":               "completed",
            "version":              new_version,
            "n_records":            len(records),
            "n_weighted_examples":  len(weighted_examples),
            "epochs":               epochs,
            "lr":                   lr,
            "train_result":         train_result,
            "reward_stats":         reward_stats,
            "timestamp":            datetime.utcnow().isoformat(),
        }

        logger.info("RLHF training cycle complete", **{
            k: v for k, v in result.items()
            if k not in ("train_result", "reward_stats")
        })

        return result

    # ── Threshold adaptation ──────────────────────────────────────────────────

    def adapt_thresholds(self, records: List[FeedbackRecord]) -> Dict:
        """
        Suggest new MCDA thresholds based on historical false-positive /
        false-negative rates from analyst feedback.

        Returns a dict of suggested threshold adjustments.
        """
        if not records:
            return {}

        fp_count  = sum(1 for r in records if r.feedback_type == "false_positive")
        fn_count  = sum(1 for r in records if r.feedback_type == "false_negative")
        total     = len(records)

        fp_rate = fp_count / total
        fn_rate = fn_count / total

        suggestions: Dict[str, float] = {}

        # If FP rate > 5% → raise thresholds (be less aggressive)
        if fp_rate > 0.05:
            delta = min(fp_rate * 0.5, 0.1)
            suggestions["HIGH_RISK_THRESHOLD"]   = round(0.75 + delta, 2)
            suggestions["MEDIUM_RISK_THRESHOLD"] = round(0.45 + delta, 2)
            suggestions["reason"] = f"FP rate {fp_rate:.1%} → raising thresholds"

        # If FN rate > 2% → lower thresholds (be more aggressive)
        elif fn_rate > 0.02:
            delta = min(fn_rate * 0.5, 0.05)
            suggestions["HIGH_RISK_THRESHOLD"]   = round(max(0.65, 0.75 - delta), 2)
            suggestions["MEDIUM_RISK_THRESHOLD"] = round(max(0.35, 0.45 - delta), 2)
            suggestions["reason"] = f"FN rate {fn_rate:.1%} → lowering thresholds"
        else:
            suggestions["reason"] = "Thresholds OK"

        suggestions.update({
            "fp_rate": fp_rate,
            "fn_rate": fn_rate,
            "total_records": total,
        })

        return suggestions


# ──────────────────────────────────────────────────────────────────────────────
# RLHF Pipeline (top-level façade)
# ──────────────────────────────────────────────────────────────────────────────

class RLHFPipeline:
    """
    Single entry-point for the entire RLHF subsystem.
    Instantiated once and shared across the application.
    """
    _instance: Optional["RLHFPipeline"] = None
    _init_lock = threading.Lock()

    def __new__(cls) -> "RLHFPipeline":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    inst = super().__new__(cls)
                    inst._setup()
                    cls._instance = inst
        return cls._instance

    def _setup(self) -> None:
        self.store    = FeedbackStore()
        self.registry = ModelRegistry()
        self.trainer  = RLHFTrainer(self.store, self.registry)
        self._bg_thread: Optional[threading.Thread] = None
        logger.info("RLHFPipeline ready")

    # ── Public API ────────────────────────────────────────────────────────────

    def submit_feedback(
        self,
        analysis_id:        str,
        subject:            str,
        body_text:          str,
        sender:             str,
        headers:            Dict,
        urls:               List[str],
        predicted_verdict:  str,
        predicted_score:    float,
        predicted_llm:      bool,
        feedback_type:      str,
        analyst_id:         str = "anonymous",
        notes:              str = "",
        corrected_verdict:  Optional[str] = None,
    ) -> str:
        """
        Submit analyst feedback and (optionally) trigger an incremental
        online update immediately.
        """
        feedback_id = str(uuid.uuid4())
        record = FeedbackRecord(
            feedback_id        = feedback_id,
            analysis_id        = analysis_id,
            subject            = subject,
            body_text          = body_text,
            sender             = sender,
            headers            = headers,
            urls               = urls,
            predicted_verdict  = predicted_verdict,
            predicted_score    = predicted_score,
            predicted_llm      = predicted_llm,
            feedback_type      = feedback_type,
            corrected_verdict  = corrected_verdict,
            analyst_id         = analyst_id,
            notes              = notes,
        )
        self.store.add(record)

        # Online update: immediately adjust weights if it's a correction
        if feedback_type in ("false_positive", "false_negative"):
            try:
                self.registry.online_update(
                    subject        = subject,
                    body           = body_text,
                    label_phishing = record.label_phishing or 0,
                    label_llm      = record.label_llm or 0,
                    sender         = sender,
                    headers        = headers,
                    urls           = urls,
                    lr             = 1e-4,  # small LR for online update
                )
                logger.info("Online RLHF update applied", feedback_id=feedback_id)
            except Exception as e:
                logger.warning("Online RLHF update failed", error=str(e))

        # Check if we should kick off a full training cycle
        if self.trainer.should_train():
            self._trigger_training_background()

        return feedback_id

    def trigger_training(
        self,
        epochs: int = 15,
        lr: float = 5e-4,
    ) -> Dict:
        """Synchronous training trigger (for Celery tasks / admin API)."""
        return self.trainer.run_training_cycle(epochs=epochs, lr=lr)

    def _trigger_training_background(self) -> None:
        """Start training in a background thread if not already running."""
        if self._bg_thread and self._bg_thread.is_alive():
            return
        self._bg_thread = threading.Thread(
            target=self._bg_train,
            daemon=True,
            name="rlhf-trainer",
        )
        self._bg_thread.start()

    def _bg_train(self) -> None:
        try:
            result = self.trainer.run_training_cycle()
            logger.info("Background RLHF training finished", status=result.get("status"))
        except Exception as e:
            logger.error("Background RLHF training failed", error=str(e))

    def get_status(self) -> Dict:
        """Return a comprehensive status report for the API."""
        store_stats    = self.store.stats()
        registry_status = self.registry.status()
        threshold_advice = self.trainer.adapt_thresholds(self.store.get_unused())

        return {
            "rlhf_enabled":        True,
            "store_stats":         store_stats,
            "registry_status":     registry_status,
            "threshold_advice":    threshold_advice,
            "training_running":    bool(self._bg_thread and self._bg_thread.is_alive()),
            "last_train_ts":       self.trainer._last_train_ts,
            "min_examples_needed": MIN_EXAMPLES_FOR_TRAINING,
        }

    def get_feedback_records(
        self,
        limit: int = 100,
        only_unused: bool = False,
    ) -> List[Dict]:
        records = (
            self.store.get_unused(limit) if only_unused
            else self.store._records[-limit:]
        )
        return [
            {
                "feedback_id":       r.feedback_id,
                "analysis_id":       r.analysis_id,
                "feedback_type":     r.feedback_type,
                "predicted_verdict": r.predicted_verdict,
                "corrected_verdict": r.corrected_verdict,
                "reward":            r.reward,
                "analyst_id":        r.analyst_id,
                "timestamp":         r.timestamp,
                "used":              r.feedback_id in self.store._used_ids,
            }
            for r in records
        ]


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton accessor
# ──────────────────────────────────────────────────────────────────────────────

def get_rlhf_pipeline() -> RLHFPipeline:
    """Return the process-level RLHFPipeline singleton."""
    return RLHFPipeline()
