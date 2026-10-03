"""
Developer 1 (Rohit Verma) — Semantic Analyst Agent
Deep NLP Transformer classification using Hugging Face pipelines.
Analyzes deep semantic intent, roleplay jailbreaks, and adversarial contexts.
"""

import time
import os
import re
from typing import Dict, Any, Optional

class SemanticAnalyst:
    def __init__(
        self,
        model_name: str = "protectai/deberta-v3-base-prompt-injection-v2",
        device: Optional[str] = None
    ):
        self.model_name = os.getenv("HF_MODEL_NAME", model_name)
        # Determine device (cpu, cuda, or mps for Apple Silicon)
        if device is None:
            configured_device = os.getenv("DETECTION_DEVICE", "cpu").lower()
            if configured_device == "cuda":
                device = "cuda"
            else:
                device = "cpu"
        self.device = device
        self._classifier = None
        self._model_load_failed = False

    def _load_model(self):
        """Lazy-loads the Hugging Face transformer pipeline with truncation guardrails."""
        if self._classifier is not None or self._model_load_failed:
            return

        try:
            from transformers import pipeline
            self._classifier = pipeline(
                "text-classification",
                model=self.model_name,
                device=self.device,
                truncation=True,
                max_length=512
            )
        except Exception as e:
            # Mark load failed so we can use resilient heuristic fallback without crashing
            self._model_load_failed = True

    def _fallback_semantic_check(self, prompt: str) -> Dict[str, Any]:
        """
        Lightweight semantic intent heuristic fallback if transformer weights
        are currently downloading or when operating completely offline.
        """
        lower = prompt.lower()
        adversarial_intent_markers = [
            "developer mode", "jailbreak", "unfiltered", "no safety", "dan mode",
            "pretend you are", "roleplay as", "hypothetical scenario where you reveal",
            "bypass your policy", "ignore your guidelines", "confidential directive",
            "master password", "override protocol", "uncensored"
        ]
        matches = [m for m in adversarial_intent_markers if m in lower]
        if matches:
            score = min(90.0, 50.0 + len(matches) * 20.0)
            return {
                "score": round(score, 2),
                "raw_label": "LABEL_1",
                "confidence": 0.85,
                "is_fallback": True
            }
        else:
            return {
                "score": 5.0,
                "raw_label": "LABEL_0",
                "confidence": 0.90,
                "is_fallback": True
            }

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Runs transformer inference with mandatory 512-token truncation and
        enforces the mandatory LABEL_0 vs LABEL_1 probability inversion.
        
        Returns:
            {
                "score": float,         # 0.0 to 100.0 (semantic injection risk)
                "raw_label": str,       # 'LABEL_0' or 'LABEL_1'
                "confidence": float,    # 0.0 to 1.0 (certainty)
                "latency_ms": float
            }
        """
        t0 = time.perf_counter()
        self._load_model()

        if self._classifier is not None:
            try:
                # Clamp input string to reasonable max length before tokenization:
                truncated_prompt = prompt[:2000]
                raw_result = self._classifier(truncated_prompt)
                
                # Raw output example: [{"label": "LABEL_0", "score": 0.985}]
                pred = raw_result[0]
                label = pred.get("label", "LABEL_0")
                prob = float(pred.get("score", 0.5))

                # Model returns "INJECTION" or "LABEL_1" for attacks, "SAFE" or "LABEL_0" for benign:
                label_upper = label.upper()
                is_attack = label_upper in ["INJECTION", "LABEL_1"] or "INJECT" in label_upper

                if is_attack:
                    semantic_risk = prob * 100.0
                else:
                    semantic_risk = (1.0 - prob) * 100.0

                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return {
                    "score": round(max(0.0, min(100.0, semantic_risk)), 2),
                    "raw_label": label,
                    "confidence": round(prob, 4),
                    "latency_ms": round(elapsed_ms, 3)
                }
            except Exception:
                pass

        # Use fallback if model inference failed or couldn't load:
        res = self._fallback_semantic_check(prompt)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        res["latency_ms"] = round(elapsed_ms, 3)
        return res
