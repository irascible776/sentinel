"""
Semantic Concept Scorer (Pillar III)
Computes cosine similarities against precomputed threat concepts and benign anchors,
evaluates margin-against-benign scores, and normalizes zero-false-positive calibrated risks.
"""

import time
from typing import List, Tuple
import torch
import torch.nn.functional as F
from PIL import Image

from core.vision.schemas import SemanticAnalysisResult, ConceptScore
from core.vision.semantic.concept_bank import concept_bank
from core.vision.semantic.mobileclip_encoder import mobileclip_encoder
from core.vision.config import (
    CONCEPT_MARGIN_FLOOR,
    CONCEPT_MARGIN_CEILING,
    DEVICE,
)


class ConceptScorer:
    """
    Evaluates zero-text visual jailbreaks and semantic threat concepts.
    Uses margin-against-benign normalization to prevent false positives on enterprise assets.
    """

    def __init__(self, device: torch.device = DEVICE):
        self.device = device
        self.bank = concept_bank
        self.encoder = mobileclip_encoder

    def score_image(self, img: Image.Image) -> SemanticAnalysisResult:
        """
        Calculates concept margins and returns calibrated semantic threat scores.
        """
        t0 = time.perf_counter()

        # Step 1: Encode image to L2-normalized 512-d vector
        img_emb, enc_latency = self.encoder.encode_image(img)

        # Step 2: Fetch precomputed threat and benign matrices
        threat_mat, benign_mat = self.bank.get_matrices(self.device)

        # Step 3: Compute cosine similarities (dot products of L2-normalized vectors)
        with torch.inference_mode():
            # (1, 512) @ (N_threats, 512).T -> (N_threats,)
            threat_cosines = torch.mv(threat_mat, img_emb).cpu().numpy()
            # (1, 512) @ (N_benign, 512).T -> (N_benign,)
            benign_cosines = torch.mv(benign_mat, img_emb).cpu().numpy()

        # Maximum similarity among all benign enterprise anchors
        max_benign_idx = int(benign_cosines.argmax())
        max_benign_cosine = float(benign_cosines[max_benign_idx])
        closest_benign_name = self.bank.benign_names[max_benign_idx]

        # Step 4: Evaluate margin-against-benign for each threat concept
        concept_scores: List[ConceptScore] = []
        max_calibrated_risk = 0.0
        max_margin = -1.0
        dominant_category = None

        for i, name in enumerate(self.bank.threat_names):
            raw_cos = float(threat_cosines[i])
            margin = raw_cos - max_benign_cosine
            category = self.bank.threat_categories[i]

            # Linear calibration between floor and ceiling
            if margin <= CONCEPT_MARGIN_FLOOR:
                calibrated_risk = 0.0
            else:
                ratio = (margin - CONCEPT_MARGIN_FLOOR) / (
                    CONCEPT_MARGIN_CEILING - CONCEPT_MARGIN_FLOOR
                )
                calibrated_risk = min(100.0, max(0.0, ratio * 100.0))

            c_score = ConceptScore(
                concept_id=name,
                category=category,
                raw_cosine=round(raw_cos, 4),
                closest_benign_anchor=closest_benign_name,
                benign_cosine=round(max_benign_cosine, 4),
                margin=round(margin, 4),
                calibrated_risk=round(calibrated_risk, 2),
            )
            concept_scores.append(c_score)

            if calibrated_risk > max_calibrated_risk:
                max_calibrated_risk = calibrated_risk
                dominant_category = category

            if margin > max_margin:
                max_margin = margin

        # Sort concepts by calibrated risk descending
        concept_scores.sort(key=lambda x: x.calibrated_risk, reverse=True)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        confidence = round(min(1.0, 0.5 + max_calibrated_risk / 200.0), 2)

        return SemanticAnalysisResult(
            model_name="MobileCLIP-S0",
            top_threat_concepts=concept_scores[:5],
            dominant_category=dominant_category if max_calibrated_risk > 0 else None,
            max_margin=round(float(max_margin), 4),
            risk_score=round(float(max_calibrated_risk), 2),
            confidence=confidence,
            latency_ms=round(elapsed_ms, 2),
        )


# Global concept scorer instance
concept_scorer = ConceptScorer()

