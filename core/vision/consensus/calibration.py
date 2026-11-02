"""
Benign Enterprise Calibration & Regression Gate (Pillar III)
Validates that model thresholds, noise baselines, and concept margins enforce
zero false positives on enterprise documents, screenshots, and financial charts.
"""

from typing import Dict, Any, List
from core.vision.schemas import (
    OCRAnalysisResult,
    SemanticAnalysisResult,
    NoiseAnalysisResult,
    StegoAnalysisResult,
    VisionVerdictEnum,
    VisionPolicyActionEnum,
)


# Reference synthetic telemetry for verified enterprise assets
BENIGN_ENTERPRISE_BENCHMARKS: List[Dict[str, Any]] = [
    {
        "name": "dark_mode_code_screenshot",
        "ocr_risk": 0.0,
        "concept_risk": 0.0,
        "noise_risk": 5.0,  # Natural high-frequency code glyphs
        "stego_risk": 0.0,
        "expected_verdict": VisionVerdictEnum.CLEAN,
        "expected_action": VisionPolicyActionEnum.ALLOW,
    },
    {
        "name": "scanned_financial_invoice",
        "ocr_risk": 10.0,  # "override" in payment terms
        "concept_risk": 0.0,
        "noise_risk": 15.0,  # Paper texture / scan noise
        "stego_risk": 0.0,
        "expected_verdict": VisionVerdictEnum.CLEAN,
        "expected_action": VisionPolicyActionEnum.ALLOW,
    },
    {
        "name": "cloud_architecture_diagram",
        "ocr_risk": 5.0,  # "kill switch" in lambda function label
        "concept_risk": 10.0,
        "noise_risk": 12.0,  # Diagram gridlines
        "stego_risk": 0.0,
        "expected_verdict": VisionVerdictEnum.CLEAN,
        "expected_action": VisionPolicyActionEnum.ALLOW,
    },
    {
        "name": "product_photo_with_tools",
        "ocr_risk": 0.0,
        "concept_risk": 15.0,  # Utility knife / wrench
        "noise_risk": 0.0,
        "stego_risk": 0.0,
        "expected_verdict": VisionVerdictEnum.CLEAN,
        "expected_action": VisionPolicyActionEnum.ALLOW,
    },
]


def verify_zero_false_positives(judge) -> bool:
    """
    Executes judgment against standard enterprise benchmarks.
    Returns True if 100% of benchmarks yield an ALLOW policy action.
    """
    for benchmark in BENIGN_ENTERPRISE_BENCHMARKS:
        ocr_res = OCRAnalysisResult(risk_score=benchmark["ocr_risk"], confidence=0.9)
        concept_res = SemanticAnalysisResult(risk_score=benchmark["concept_risk"], confidence=0.8)
        noise_res = NoiseAnalysisResult(risk_score=benchmark["noise_risk"])
        stego_res = StegoAnalysisResult(risk_score=benchmark["stego_risk"])

        risk, verdict, action, sigs, _ = judge.arbitrate(
            ocr_res=ocr_res,
            concept_res=concept_res,
            noise_res=noise_res,
            stego_res=stego_res,
        )

        if action != VisionPolicyActionEnum.ALLOW:
            return False

    return True

