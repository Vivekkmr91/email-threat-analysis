"""
Celery application instance and task definitions.

Tasks
-----
run_rlhf_training_cycle    – Trigger RLHF training from collected feedback
run_batch_ml_training      – Train ML models from a provided labelled dataset
check_and_auto_train       – Periodic check: train if enough feedback exists
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

import structlog
from celery import Celery
from celery.schedules import crontab

from app.core.config import settings
from app.core.logging import setup_logging

setup_logging()
logger = structlog.get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Celery app
# ──────────────────────────────────────────────────────────────────────────────

celery_app = Celery(
    "email_threat_analysis",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer        = "json",
    result_serializer      = "json",
    accept_content         = ["json"],
    timezone               = "UTC",
    enable_utc             = True,
    task_track_started     = True,
    task_acks_late         = True,
    worker_prefetch_multiplier = 1,
    result_expires         = 3600,           # 1 hour
    task_soft_time_limit   = 1800,           # 30 min
    task_time_limit        = 2100,           # 35 min hard limit
    # Beat schedule: auto-train every 6 hours
    beat_schedule = {
        "auto-rlhf-training": {
            "task":     "app.workers.celery_app.check_and_auto_train",
            "schedule": crontab(minute=0, hour="*/6"),  # every 6 hours
        },
    },
)


# ──────────────────────────────────────────────────────────────────────────────
# Tasks
# ──────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    name="app.workers.celery_app.run_rlhf_training_cycle",
    bind=True,
    max_retries=2,
    default_retry_delay=300,
)
def run_rlhf_training_cycle(
    self,
    epochs:     int   = 15,
    lr:         float = 5e-4,
    batch_size: int   = 32,
) -> Dict:
    """
    Run one full RLHF training cycle using accumulated analyst feedback.
    Triggered manually via the API or automatically by beat schedule.
    """
    task_id = self.request.id
    logger.info("RLHF training task started", task_id=task_id, epochs=epochs, lr=lr)

    try:
        from app.ml.rlhf import get_rlhf_pipeline
        pipeline = get_rlhf_pipeline()

        store_stats = pipeline.store.stats()
        logger.info("Feedback store stats", **store_stats)

        if store_stats["unused_feedback"] == 0:
            result = {
                "status": "skipped",
                "reason": "no_unused_feedback",
                "task_id": task_id,
            }
            logger.info("RLHF training skipped – no unused feedback")
            return result

        result = pipeline.trigger_training(epochs=epochs, lr=lr)
        result["task_id"] = task_id

        logger.info(
            "RLHF training task complete",
            task_id=task_id,
            status=result.get("status"),
            version=result.get("version"),
        )
        return result

    except Exception as exc:
        logger.error("RLHF training task failed", task_id=task_id, error=str(exc))
        raise self.retry(exc=exc)


@celery_app.task(
    name="app.workers.celery_app.run_batch_ml_training",
    bind=True,
    max_retries=1,
    default_retry_delay=60,
)
def run_batch_ml_training(
    self,
    examples:   List[Dict],
    epochs:     int   = 20,
    lr:         float = 1e-3,
    batch_size: int   = 32,
) -> Dict:
    """
    Train ML models on a provided labelled dataset.
    Each example must contain:
      subject, body, sender, headers (opt), urls (opt),
      label_phishing (0/1), label_llm (0/1)
    """
    task_id = self.request.id
    logger.info(
        "Batch ML training task started",
        task_id=task_id,
        n_examples=len(examples),
        epochs=epochs,
    )

    try:
        from app.ml.phishing_classifier import get_registry
        registry = get_registry()

        result = registry.batch_train(
            examples=examples,
            epochs=epochs,
            lr=lr,
            batch_size=batch_size,
        )
        result["task_id"] = task_id

        logger.info(
            "Batch ML training task complete",
            task_id=task_id,
            phishing_acc=result.get("phishing_accuracy"),
            llm_acc=result.get("llm_detect_accuracy"),
        )
        return result

    except Exception as exc:
        logger.error("Batch ML training task failed", task_id=task_id, error=str(exc))
        raise self.retry(exc=exc)


@celery_app.task(name="app.workers.celery_app.check_and_auto_train")
def check_and_auto_train() -> Dict:
    """
    Periodic beat task: check if training conditions are met and trigger
    a training cycle automatically.
    """
    logger.info("Auto-train check started")

    try:
        from app.ml.rlhf import get_rlhf_pipeline
        pipeline = get_rlhf_pipeline()

        if pipeline.trainer.should_train():
            logger.info("Auto-train: conditions met, starting training cycle")
            result = pipeline.trigger_training()
            return {"triggered": True, "result": result}
        else:
            stats = pipeline.store.stats()
            logger.info(
                "Auto-train: conditions not met",
                unused_feedback=stats["unused_feedback"],
            )
            return {"triggered": False, "store_stats": stats}

    except Exception as e:
        logger.error("Auto-train check failed", error=str(e))
        return {"triggered": False, "error": str(e)}
