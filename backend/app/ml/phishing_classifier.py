"""
Custom ML Phishing / LLM-Generation Classifier
===============================================

Architecture
------------
Two cooperating models are maintained in a single ModelRegistry:

1. **PhishingClassifier**
   - Input : 60-feature vector from `features.extract_features()`
   - Architecture: 3-layer MLP (60 → 128 → 64 → 2)
   - Output : probability of [clean, phishing]

2. **LLMGenerationDetector**
   - Input : same 60-feature vector
   - Focus on LLM fingerprint + linguistic features
   - Output : probability of [human-written, llm-generated]

Both models are written in pure NumPy (no heavy framework) so they can
run **without GPU** in any environment.  When a trained checkpoint exists
(saved as a .npz file) it is loaded; otherwise the models are randomly
initialised and will produce ~random predictions until fine-tuned via the
RLHF pipeline.

The ModelRegistry is a process-level singleton that is thread-safe for
prediction and uses a write-lock for updates.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import structlog

from app.ml.features import extract_features, FEATURE_NAMES

logger = structlog.get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Hyper-parameters
# ──────────────────────────────────────────────────────────────────────────────

PHISHING_ARCH   = [60, 128, 64, 2]   # layer sizes
LLM_DETECT_ARCH = [60, 64, 32, 2]

MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", "/tmp/email_threat_ml"))
MODEL_DIR.mkdir(parents=True, exist_ok=True)

PHISHING_CKPT    = MODEL_DIR / "phishing_classifier.npz"
LLM_DETECT_CKPT  = MODEL_DIR / "llm_detector.npz"

PREDICTION_THRESHOLD = 0.5   # above → phishing / llm-generated


# ──────────────────────────────────────────────────────────────────────────────
# Activation helpers
# ──────────────────────────────────────────────────────────────────────────────

def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0.0, x)


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max())
    return e / e.sum()


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -30, 30)))


# ──────────────────────────────────────────────────────────────────────────────
# Minimal MLP (inference only)
# ──────────────────────────────────────────────────────────────────────────────

class MLP:
    """
    Lightweight multi-layer perceptron for binary/multiclass classification.

    Layers: [Linear → ReLU] × (n-1)  →  Linear → Softmax
    Weights are stored as numpy arrays and can be updated atomically.
    """

    def __init__(self, layer_sizes: List[int], seed: int = 42):
        rng = np.random.RandomState(seed)
        self.layers: List[Tuple[np.ndarray, np.ndarray]] = []
        for i in range(len(layer_sizes) - 1):
            fan_in  = layer_sizes[i]
            fan_out = layer_sizes[i + 1]
            # Xavier initialisation
            limit = math.sqrt(6.0 / (fan_in + fan_out))
            W = rng.uniform(-limit, limit, (fan_out, fan_in)).astype(np.float32)
            b = np.zeros(fan_out, dtype=np.float32)
            self.layers.append((W, b))

    # ── Forward pass ─────────────────────────────────────────────────────────

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        """
        Run forward pass.
        x : (n_features,) or (batch, n_features)
        returns softmax probabilities
        """
        batched = x.ndim == 2
        if not batched:
            x = x[np.newaxis, :]          # (1, n)

        h = x.astype(np.float32)
        for i, (W, b) in enumerate(self.layers):
            h = h @ W.T + b                # (batch, fan_out)
            if i < len(self.layers) - 1:
                h = _relu(h)

        # Softmax over last dim
        proba = np.array([_softmax(row) for row in h])
        return proba if batched else proba[0]

    def predict(self, x: np.ndarray) -> int:
        proba = self.predict_proba(x)
        if proba.ndim == 1:
            return int(np.argmax(proba))
        return int(np.argmax(proba, axis=1)[0])

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> Dict:
        return {
            f"W_{i}": W for i, (W, _) in enumerate(self.layers)
        } | {
            f"b_{i}": b for i, (_, b) in enumerate(self.layers)
        }

    @classmethod
    def from_dict(cls, d: Dict, layer_sizes: List[int]) -> "MLP":
        model = cls(layer_sizes)   # random init (will be overwritten)
        for i in range(len(layer_sizes) - 1):
            model.layers[i] = (d[f"W_{i}"], d[f"b_{i}"])
        return model

    def save(self, path: Path) -> None:
        np.savez(str(path), **self.to_dict())
        logger.debug("Model saved", path=str(path))

    @classmethod
    def load(cls, path: Path, layer_sizes: List[int]) -> "MLP":
        data = np.load(str(path))
        d = {k: data[k] for k in data.files}
        logger.info("Model loaded from checkpoint", path=str(path))
        return cls.from_dict(d, layer_sizes)

    # ── Mini-batch SGD update (used by RLHF trainer) ─────────────────────────

    def sgd_step(
        self,
        x: np.ndarray,           # (batch, n_features)
        y: np.ndarray,           # (batch,)  integer labels
        lr: float = 1e-3,
        l2: float = 1e-4,
    ) -> float:
        """
        One SGD step with cross-entropy loss.
        Returns scalar loss value.
        """
        batch = x.shape[0]
        # Forward
        activations = [x.astype(np.float32)]
        h = activations[0]
        for i, (W, b) in enumerate(self.layers):
            z = h @ W.T + b
            if i < len(self.layers) - 1:
                h = _relu(z)
            else:
                # softmax
                e  = np.exp(z - z.max(axis=1, keepdims=True))
                h  = e / e.sum(axis=1, keepdims=True)
            activations.append(h)

        proba = activations[-1]

        # Cross-entropy loss
        eps  = 1e-9
        loss = -np.mean(np.log(proba[np.arange(batch), y] + eps))

        # Backward (manual backprop through softmax + cross-entropy)
        delta = proba.copy()
        delta[np.arange(batch), y] -= 1.0
        delta /= batch

        new_layers = []
        for i in reversed(range(len(self.layers))):
            W, b = self.layers[i]
            a_prev = activations[i]          # input to layer i

            dW = delta.T @ a_prev + l2 * W   # (fan_out, fan_in)
            db = delta.sum(axis=0)            # (fan_out,)

            if i > 0:
                # Propagate delta through ReLU
                delta_prev = delta @ W        # (batch, fan_in)
                delta_prev[activations[i] <= 0] = 0.0   # ReLU mask
                delta = delta_prev

            new_W = W - lr * dW
            new_b = b - lr * db
            new_layers.append((new_W, new_b))

        self.layers = list(reversed(new_layers))
        return float(loss)


# ──────────────────────────────────────────────────────────────────────────────
# Prediction result
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MLPrediction:
    """Unified prediction result from the ML layer."""
    phishing_score: float        # 0-1 probability of being phishing
    llm_generated_score: float   # 0-1 probability of being LLM-generated
    is_phishing: bool
    is_llm_generated: bool
    feature_vector: List[float]
    top_features: List[Dict]     # [{name, value, importance}] top 10
    model_version: str
    inference_time_ms: float


# ──────────────────────────────────────────────────────────────────────────────
# Feature importance (via gradient approximation / input permutation)
# ──────────────────────────────────────────────────────────────────────────────

def _get_top_features(
    model: MLP,
    x: np.ndarray,
    n: int = 10,
) -> List[Dict]:
    """
    Approximate feature importance by measuring the change in output
    when each feature is zeroed-out (ablation).
    Returns top-n features sorted by importance.
    """
    baseline = model.predict_proba(x)[1]  # phishing probability
    importances = []
    for i in range(len(x)):
        x_masked = x.copy()
        x_masked[i] = 0.0
        masked_score = model.predict_proba(x_masked)[1]
        importances.append(abs(baseline - masked_score))

    # Rank
    ranked = sorted(
        enumerate(importances), key=lambda t: t[1], reverse=True
    )[:n]

    return [
        {
            "feature_name": FEATURE_NAMES[i],
            "feature_value": float(x[i]),
            "importance":    float(imp),
        }
        for i, imp in ranked
    ]


# ──────────────────────────────────────────────────────────────────────────────
# Model Registry (singleton)
# ──────────────────────────────────────────────────────────────────────────────

class ModelRegistry:
    """
    Thread-safe singleton that holds trained model weights and exposes
    predict() and update_weights() methods.
    """
    _instance: Optional["ModelRegistry"] = None
    _lock     = threading.Lock()

    def __new__(cls) -> "ModelRegistry":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    inst = super().__new__(cls)
                    inst._init()
                    cls._instance = inst
        return cls._instance

    def _init(self) -> None:
        self._model_lock = threading.RLock()
        self._version    = "0.0.0"
        self._phishing_model   = self._load_or_init(PHISHING_CKPT,   PHISHING_ARCH, seed=1)
        self._llm_detect_model = self._load_or_init(LLM_DETECT_CKPT, LLM_DETECT_ARCH, seed=2)
        # Training statistics
        self._train_stats: Dict = {
            "total_examples": 0,
            "total_updates":  0,
            "last_update_ts": None,
            "phishing_accuracy":    None,
            "llm_detect_accuracy":  None,
        }
        logger.info("ModelRegistry initialised", version=self._version)

    @staticmethod
    def _load_or_init(ckpt: Path, arch: List[int], seed: int) -> MLP:
        if ckpt.exists():
            try:
                return MLP.load(ckpt, arch)
            except Exception as e:
                logger.warning("Failed to load checkpoint, using random init",
                               path=str(ckpt), error=str(e))
        return MLP(arch, seed=seed)

    # ── Prediction ───────────────────────────────────────────────────────────

    def predict(
        self,
        subject:  str,
        body:     str,
        sender:   str = "",
        headers:  Optional[Dict] = None,
        urls:     Optional[List[str]] = None,
    ) -> MLPrediction:
        t0 = time.perf_counter()
        x = extract_features(subject, body, sender, headers, urls)

        with self._model_lock:
            p_proba  = self._phishing_model.predict_proba(x)
            l_proba  = self._llm_detect_model.predict_proba(x)
            version  = self._version
            # Top contributing features (uses phishing model)
            top_feats = _get_top_features(self._phishing_model, x, n=10)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        phishing_score    = float(p_proba[1])
        llm_score         = float(l_proba[1])

        return MLPrediction(
            phishing_score      = phishing_score,
            llm_generated_score = llm_score,
            is_phishing         = phishing_score >= PREDICTION_THRESHOLD,
            is_llm_generated    = llm_score       >= PREDICTION_THRESHOLD,
            feature_vector      = x.tolist(),
            top_features        = top_feats,
            model_version       = version,
            inference_time_ms   = elapsed_ms,
        )

    # ── Weight update (called by RLHF trainer) ───────────────────────────────

    def update_weights(
        self,
        phishing_weights:   Optional[Dict] = None,
        llm_detect_weights: Optional[Dict] = None,
        version:            str = "",
        stats:              Optional[Dict] = None,
    ) -> None:
        with self._model_lock:
            if phishing_weights:
                self._phishing_model = MLP.from_dict(
                    phishing_weights, PHISHING_ARCH
                )
                self._phishing_model.save(PHISHING_CKPT)

            if llm_detect_weights:
                self._llm_detect_model = MLP.from_dict(
                    llm_detect_weights, LLM_DETECT_ARCH
                )
                self._llm_detect_model.save(LLM_DETECT_CKPT)

            if version:
                self._version = version

            if stats:
                self._train_stats.update(stats)

        logger.info("Model weights updated", version=version or self._version)

    # ── Incremental online learning (single example) ─────────────────────────

    def online_update(
        self,
        subject:       str,
        body:          str,
        label_phishing:    int,   # 0 = clean, 1 = phishing
        label_llm:         int,   # 0 = human, 1 = llm-generated
        sender:        str = "",
        headers:       Optional[Dict] = None,
        urls:          Optional[List[str]] = None,
        lr:            float = 5e-4,
    ) -> Dict:
        x = extract_features(subject, body, sender, headers, urls)
        x_batch = x[np.newaxis, :]

        with self._model_lock:
            p_loss = self._phishing_model.sgd_step(
                x_batch, np.array([label_phishing]), lr=lr
            )
            l_loss = self._llm_detect_model.sgd_step(
                x_batch, np.array([label_llm]), lr=lr
            )
            self._train_stats["total_examples"] += 1
            self._train_stats["total_updates"]  += 1
            self._train_stats["last_update_ts"]  = time.time()

        return {"phishing_loss": p_loss, "llm_loss": l_loss}

    # ── Batch training (called by Celery task) ───────────────────────────────

    def batch_train(
        self,
        examples: List[Dict],   # [{subject, body, sender, headers, urls,
                                #    label_phishing, label_llm}]
        epochs:   int = 10,
        lr:       float = 1e-3,
        batch_size: int = 32,
    ) -> Dict:
        """
        Fine-tune both models on a list of labelled examples.
        Returns training statistics.
        """
        if not examples:
            return {"status": "no_data"}

        X = np.array([
            extract_features(
                e["subject"], e["body"],
                e.get("sender", ""),
                e.get("headers"),
                e.get("urls"),
            )
            for e in examples
        ], dtype=np.float32)

        y_phish = np.array([e["label_phishing"] for e in examples], dtype=int)
        y_llm   = np.array([e["label_llm"]      for e in examples], dtype=int)

        n = len(X)
        rng = np.random.RandomState(0)

        p_losses: List[float] = []
        l_losses: List[float] = []

        with self._model_lock:
            for epoch in range(epochs):
                idx = rng.permutation(n)
                X, y_phish, y_llm = X[idx], y_phish[idx], y_llm[idx]

                for start in range(0, n, batch_size):
                    end = start + batch_size
                    Xb = X[start:end]
                    yp = y_phish[start:end]
                    yl = y_llm[start:end]

                    pl = self._phishing_model.sgd_step(Xb, yp, lr=lr)
                    ll = self._llm_detect_model.sgd_step(Xb, yl, lr=lr)
                    p_losses.append(pl)
                    l_losses.append(ll)

            # Compute post-training accuracy
            p_preds = np.argmax(self._phishing_model.predict_proba(X), axis=1)
            l_preds = np.argmax(self._llm_detect_model.predict_proba(X), axis=1)
            p_acc   = float(np.mean(p_preds == y_phish))
            l_acc   = float(np.mean(l_preds == y_llm))

            # Save checkpoints
            self._phishing_model.save(PHISHING_CKPT)
            self._llm_detect_model.save(LLM_DETECT_CKPT)

            stats = {
                "total_examples":       n,
                "total_updates":        self._train_stats.get("total_updates", 0) + epochs * n,
                "last_update_ts":       time.time(),
                "phishing_accuracy":    p_acc,
                "llm_detect_accuracy":  l_acc,
            }
            self._train_stats.update(stats)

        logger.info(
            "Batch training complete",
            n_examples=n,
            epochs=epochs,
            phishing_acc=p_acc,
            llm_acc=l_acc,
        )

        return {
            "status":               "completed",
            "n_examples":           n,
            "epochs":               epochs,
            "final_phishing_loss":  float(np.mean(p_losses[-n:])) if p_losses else None,
            "final_llm_loss":       float(np.mean(l_losses[-n:])) if l_losses else None,
            "phishing_accuracy":    p_acc,
            "llm_detect_accuracy":  l_acc,
        }

    # ── Status / info ─────────────────────────────────────────────────────────

    def status(self) -> Dict:
        with self._model_lock:
            return {
                "model_version": self._version,
                "train_stats":   dict(self._train_stats),
                "phishing_arch": PHISHING_ARCH,
                "llm_arch":      LLM_DETECT_ARCH,
                "phishing_ckpt_exists":    PHISHING_CKPT.exists(),
                "llm_detect_ckpt_exists":  LLM_DETECT_CKPT.exists(),
            }


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton accessor
# ──────────────────────────────────────────────────────────────────────────────

def get_registry() -> ModelRegistry:
    """Return the process-level ModelRegistry singleton."""
    return ModelRegistry()
