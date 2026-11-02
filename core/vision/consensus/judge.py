"""
Corroboration-Gated Consensus Judge (Pillar III)
Arbitrates multi-modal vision signals into definitive policy decisions
(ALLOW, FLAG, BLOCK, REDACT_IMAGE) using two-layer corroboration gating.
"""

from typing import List, Tuple, Dict, Any, Optional
from core.vision.schemas import (
    OCRAnalysisResult,
    SemanticAnalysisResult,
    NoiseAnalysisResult,
    StegoAnalysisResult,
    VisionVerdictEnum,
    VisionPolicyActionEnum,
)
from core.vision.config import (
    RISK_THRESHOLD_ALLOW,
    RISK_THRESHOLD_BLOCK,
    SOLO_SOFT_CHANNEL_MAX_SCORE,
    CONCEPT_SOLO_CERTAINTY_THRESHOLD,
)


class VisionJudge:
    """
    Master consensus engine for Pillar III Vision & Document inspection.
    Enforces deterministic short-circuits and cross-channel corroboration gates.
    """

    def arbitrate(
        self,
        ocr_res: OCRAnalysisResult,
        concept_res: SemanticAnalysisResult,
        noise_res: NoiseAnalysisResult,
        stego_res: StegoAnalysisResult,
        allow_redaction: bool = False,
    ) -> Tuple[float, VisionVerdictEnum, VisionPolicyActionEnum, List[str], str]:
        """
        Executes multi-channel consensus arbitration.

        Returns:
            (composite_risk, verdict, policy_action, matched_signatures, reasoning)
        """
        matched_signatures: List[str] = []

        # ── Layer 1: Deterministic Oracles (Short-circuit to immediate BLOCK) ─────────
        # 1. Canary Token match in OCR text
        canary_hit = any("CANARY" in s for s in ocr_res.matched_signatures) or (
            "CANARY-SECRET-" in ocr_res.raw_text
        )
        if canary_hit:
            matched_signatures.append("CANARY:ORACLE_HIT")
            return (
                95.0,
                VisionVerdictEnum.VISUAL_INJECTION,
                VisionPolicyActionEnum.BLOCK,
                matched_signatures,
                "Deterministic block: System canary token detected in visual text.",
            )

        # 2. High-confidence text injection signature
        has_high_sig = any(
            s in ocr_res.matched_signatures
            for s in ("SIG-001", "SIG-002", "SIG-003", "SIG-005")
        ) or (ocr_res.risk_score >= 85.0 and ocr_res.confidence >= 0.85)

        if has_high_sig:
            matched_signatures.extend(ocr_res.matched_signatures)
            matched_signatures.append("OCR:DIRECT_INJECTION")
            # Check if spatially localizable for redaction
            if allow_redaction and ocr_res.spans:
                return (
                    85.0,
                    VisionVerdictEnum.VISUAL_INJECTION,
                    VisionPolicyActionEnum.REDACT_IMAGE,
                    matched_signatures,
                    "Visual prompt injection detected in rendered text; localized redaction applied.",
                )
            return (
                85.0,
                VisionVerdictEnum.VISUAL_INJECTION,
                VisionPolicyActionEnum.BLOCK,
                matched_signatures,
                "Deterministic block: High-confidence prompt injection detected in visual text.",
            )

        # ── Layer 2: Soft Probabilistic Channels & Corroboration ──────────────────────
        elevated_families = []

        # Family A: Text Ingress Risk
        if ocr_res.risk_score >= 40.0:
            elevated_families.append("TEXT")
            matched_signatures.extend(ocr_res.matched_signatures)

        # Family B: Semantic Concept Risk (Zero-Text)
        if concept_res.risk_score >= 50.0:
            elevated_families.append("SEMANTIC")
            if concept_res.dominant_category:
                matched_signatures.append(f"CONCEPT:{concept_res.dominant_category}")

        # Family C: Forensic Noise & Steganography
        if noise_res.is_adversarial_noise or noise_res.risk_score >= 60.0:
            elevated_families.append("FORENSIC_NOISE")
            matched_signatures.append("NOISE:ADVERSARIAL_PERTURBATION")

        if stego_res.is_stego or stego_res.risk_score >= 70.0:
            elevated_families.append("FORENSIC_STEGO")
            matched_signatures.append("STEGO:LSB_CHI_SQUARE")

        distinct_families = set(elevated_families)
        peak_soft_score = max(
            ocr_res.risk_score,
            concept_res.risk_score,
            noise_res.risk_score,
            stego_res.risk_score,
        )

        # ── Corroboration Rules ───────────────────────────────────────────────────────
        if len(distinct_families) == 0:
            # All channels clean
            composite_risk = max(0.0, peak_soft_score * 0.5)
            verdict = VisionVerdictEnum.CLEAN
            policy_action = VisionPolicyActionEnum.ALLOW
            reasoning = "Visual content verified clean across all inspection channels."

        elif len(distinct_families) == 1:
            # Solo elevated channel -> CLAMP AT FLAG (Enforces Zero False Positive Mandate)
            # Exception: extreme certainty (e.g. concept score >= 92.0)
            if peak_soft_score >= CONCEPT_SOLO_CERTAINTY_THRESHOLD:
                composite_risk = peak_soft_score
                verdict = VisionVerdictEnum.MALICIOUS
                policy_action = VisionPolicyActionEnum.BLOCK
                reasoning = (
                    f"Blocked on extreme certainty: {list(distinct_families)[0]} "
                    f"confidence exceeded certainty threshold ({peak_soft_score:.1f})."
                )
            else:
                composite_risk = min(SOLO_SOFT_CHANNEL_MAX_SCORE, max(45.0, peak_soft_score))
                verdict = VisionVerdictEnum.SUSPICIOUS
                policy_action = VisionPolicyActionEnum.FLAG
                reasoning = (
                    f"Flagged for analyst review: uncorroborated anomaly in {list(distinct_families)[0]} "
                    f"channel (score: {peak_soft_score:.1f}). Forwarded with monitoring."
                )

        else:
            # Two or more distinct families corroborated -> ESCALATE TO BLOCK
            composite_risk = max(80.0, peak_soft_score)
            verdict = VisionVerdictEnum.MALICIOUS
            policy_action = VisionPolicyActionEnum.BLOCK
            reasoning = (
                f"Blocked: Multi-channel threat corroboration across {', '.join(sorted(distinct_families))} "
                f"(composite risk: {composite_risk:.1f})."
            )

        return (
            round(composite_risk, 2),
            verdict,
            policy_action,
            matched_signatures,
            reasoning,
        )


# Global vision judge instance
vision_judge = VisionJudge()

