"""
Pydantic Schemas for Pillar III: Vision & Document Threat Detection Engine
Strict typing for OCR spans, MobileCLIP concept margins, SRM noise metrics,
hidden-text document findings, consensus decisions, and localized redactions.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from pydantic import BaseModel, Field


class VisionVerdictEnum(str, Enum):
    CLEAN = "CLEAN"
    BENIGN_ENTERPRISE = "BENIGN_ENTERPRISE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    VISUAL_INJECTION = "VISUAL_INJECTION"
    STEGANOGRAPHY = "STEGANOGRAPHY"
    ADVERSARIAL_PERTURBATION = "ADVERSARIAL_PERTURBATION"
    CORRUPT_UNSCANNABLE = "CORRUPT_UNSCANNABLE"


class VisionPolicyActionEnum(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"
    REDACT_IMAGE = "REDACT_IMAGE"


class BoundingBox(BaseModel):
    x1: float = Field(ge=0.0, description="Normalized or absolute left coordinate")
    y1: float = Field(ge=0.0, description="Normalized or absolute top coordinate")
    x2: float = Field(ge=0.0, description="Normalized or absolute right coordinate")
    y2: float = Field(ge=0.0, description="Normalized or absolute bottom coordinate")
    is_normalized: bool = True

    def to_pixel_box(self, img_width: int, img_height: int) -> Tuple[int, int, int, int]:
        """Convert normalized (0.0 - 1.0) coordinates to integer pixel coordinates."""
        if not self.is_normalized:
            return int(self.x1), int(self.y1), int(self.x2), int(self.y2)
        return (
            max(0, min(img_width, int(self.x1 * img_width))),
            max(0, min(img_height, int(self.y1 * img_height))),
            max(0, min(img_width, int(self.x2 * img_width))),
            max(0, min(img_height, int(self.y2 * img_height))),
        )


class OCRSpan(BaseModel):
    text: str
    box: BoundingBox
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    is_suspicious: bool = False
    matched_patterns: List[str] = Field(default_factory=list)


class OCRAnalysisResult(BaseModel):
    backend: str = "none"  # "easyocr", "tesseract", "mock", "bypassed_fast_path"
    has_text: bool = False
    raw_text: str = ""
    spans: List[OCRSpan] = Field(default_factory=list)
    risk_score: float = 0.0  # 0.0 to 100.0 from text ingress pipeline
    confidence: float = 0.0
    matched_signatures: List[str] = Field(default_factory=list)
    latency_ms: float = 0.0


class ConceptScore(BaseModel):
    concept_id: str
    category: str  # "WEAPON", "CBRN", "VIOLENCE", "CONTRABAND", "BYPASS", "JAILBREAK"
    raw_cosine: float
    closest_benign_anchor: str
    benign_cosine: float
    margin: float
    calibrated_risk: float = 0.0  # 0.0 to 100.0


class SemanticAnalysisResult(BaseModel):
    model_name: str = "MobileCLIP-S0"
    top_threat_concepts: List[ConceptScore] = Field(default_factory=list)
    dominant_category: Optional[str] = None
    max_margin: float = 0.0
    risk_score: float = 0.0
    confidence: float = 0.0
    latency_ms: float = 0.0


class NoiseAnalysisResult(BaseModel):
    srm_energy: float = 0.0
    edge_residual_correlation: float = 0.0  # 0.0 to 1.0
    flat_region_leakage: float = 0.0
    is_adversarial_noise: bool = False
    risk_score: float = 0.0
    latency_ms: float = 0.0


class StegoAnalysisResult(BaseModel):
    lsb_chi_square_p_value: float = 0.0
    degrees_of_freedom: int = 127
    num_povs_evaluated: int = 0
    is_stego: bool = False
    risk_score: float = 0.0
    latency_ms: float = 0.0


class DocHiddenTextFinding(BaseModel):
    page_num: int
    rule_type: str  # "RENDER_MODE_3", "COLOR_DISTANCE", "MICRO_FONT", "OFF_CANVAS", "OOXML_VANISH"
    text: str
    font_size: float = 0.0
    effective_font_size: float = 0.0
    delta_e: Optional[float] = None
    box: Optional[BoundingBox] = None
    severity: str = "HIGH"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"


class PageScanResult(BaseModel):
    page_num: int
    text_length: int = 0
    findings: List[DocHiddenTextFinding] = Field(default_factory=list)
    embedded_images_count: int = 0
    embedded_image_risks: List[float] = Field(default_factory=list)
    page_risk_score: float = 0.0


class DocScanResult(BaseModel):
    sha256: str
    filename: str
    format: str  # "PDF", "DOCX", "UNKNOWN"
    total_pages: int = 0
    composite_risk_score: float = 0.0
    verdict: VisionVerdictEnum = VisionVerdictEnum.CLEAN
    policy_action: VisionPolicyActionEnum = VisionPolicyActionEnum.ALLOW
    pages: List[PageScanResult] = Field(default_factory=list)
    findings: List[DocHiddenTextFinding] = Field(default_factory=list)
    matched_signatures: List[str] = Field(default_factory=list)
    scan_latency_ms: float = 0.0
    reasoning: str = ""
    cached: bool = False


class VisionScanResult(BaseModel):
    sha256: str
    filename: str
    width: int = 0
    height: int = 0
    format: str = "PNG"
    has_text: bool = False
    verdict: VisionVerdictEnum = VisionVerdictEnum.CLEAN
    policy_action: VisionPolicyActionEnum = VisionPolicyActionEnum.ALLOW
    composite_risk_score: float = 0.0
    confidence: float = 1.0
    scan_latency_ms: float = 0.0
    ocr_analysis: OCRAnalysisResult = Field(default_factory=OCRAnalysisResult)
    concept_analysis: SemanticAnalysisResult = Field(default_factory=SemanticAnalysisResult)
    noise_analysis: NoiseAnalysisResult = Field(default_factory=NoiseAnalysisResult)
    stego_analysis: StegoAnalysisResult = Field(default_factory=StegoAnalysisResult)
    matched_signatures: List[str] = Field(default_factory=list)
    reasoning: str = "Image verified clean."
    redacted_image_base64: Optional[str] = None
    cached: bool = False

