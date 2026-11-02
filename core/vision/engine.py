"""
Master Vision & Document Threat Engine Coordinator (Pillar III)
Thread-safe lazy-loading, SHA-256 LRU cache, single-fetch pixel canonicalization,
and end-to-end multi-modal security inspection pipeline.
"""

import io
import time
import hashlib
import threading
from typing import Dict, Any, Optional, Tuple
from PIL import Image
import torch

from core.vision.config import (
    DEFAULT_LRU_CACHE_SIZE,
    SCAN_TIMEOUT_SECONDS,
)
from core.vision.schemas import (
    VisionScanResult,
    DocScanResult,
    OCRAnalysisResult,
    OCRSpan,
    BoundingBox,
    VisionVerdictEnum,
    VisionPolicyActionEnum,
)
from core.vision.preprocessing.image_prep import canonicalize_image, preprocess_for_ocr
from core.vision.preprocessing.text_presence import detect_text_presence
from core.vision.ocr.factory import OCRFactory
from core.vision.semantic.concept_scorer import concept_scorer
from core.vision.srm.pgd_detector import pgd_noise_detector
from core.vision.srm.lsb_detector import lsb_stego_detector
from core.vision.document.pdf_parser import pdf_threat_parser
from core.vision.document.docx_parser import docx_threat_parser
from core.vision.document.page_aggregator import page_aggregator
from core.vision.redaction.redactor import image_redactor
from core.vision.consensus.judge import vision_judge

# Ingress Text Ensemble Reuse
from core.detection.normalizer import normalize_text
from core.detection.pattern_hunter import PatternHunter
from core.detection.semantic_analyst import SemanticAnalyst


class VisionEngine:
    """
    Master in-process coordinator for Pillar III Vision & Document Threat Inspection.
    Coordinates preprocessing, OCR, MobileCLIP, SRM filtering, and consensus arbitration.
    """

    def __init__(self, cache_size: int = DEFAULT_LRU_CACHE_SIZE):
        self._load_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._cache_size = cache_size
        self._image_cache: Dict[str, VisionScanResult] = {}
        self._doc_cache: Dict[str, DocScanResult] = {}

        # Lazy components
        self._ocr_engine = None
        self._pattern_hunter = None
        self._semantic_analyst = None
        self._initialized = False

    def _lazy_init(self):
        """Thread-safe lazy initialization for detection models."""
        if self._initialized:
            return

        with self._load_lock:
            if self._initialized:
                return

            self._ocr_engine = OCRFactory.get_engine()
            self._pattern_hunter = PatternHunter()
            self._semantic_analyst = SemanticAnalyst()
            self._initialized = True

    def scan_image(
        self,
        image_bytes: bytes,
        filename: str = "image.png",
        allow_redaction: bool = False,
    ) -> VisionScanResult:
        """
        Executes end-to-end multi-modal vision threat inspection.
        """
        start_time = time.perf_counter()
        self._lazy_init()

        # Step 0: SHA-256 Cache Check
        img_sha256 = hashlib.sha256(image_bytes).hexdigest()
        cache_key = f"{img_sha256}_{allow_redaction}"

        with self._cache_lock:
            if cache_key in self._image_cache:
                cached = self._image_cache[cache_key].model_copy()
                cached.cached = True
                cached.scan_latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                return cached

        # Step 1: Pixel Canonicalization & Anti-TOCTOU Re-encoding
        try:
            canonical_img, canonical_bytes, meta = canonicalize_image(image_bytes)
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return VisionScanResult(
                sha256=img_sha256,
                filename=filename,
                format="UNKNOWN",
                verdict=VisionVerdictEnum.CORRUPT_UNSCANNABLE,
                policy_action=VisionPolicyActionEnum.BLOCK,
                composite_risk_score=95.0,
                confidence=1.0,
                scan_latency_ms=round(elapsed_ms, 2),
                reasoning=f"Corrupt or invalid image stream: {str(e)}",
            )

        # Step 2: Two-Stage Text Presence Gate (Fast Path)
        has_text, text_conf, text_metrics = detect_text_presence(canonical_img)

        ocr_res = OCRAnalysisResult()
        suspicious_spans: list = []

        if not has_text:
            # Bypass heavy OCR on clean visual photos
            ocr_res = OCRAnalysisResult(
                backend="bypassed_fast_path",
                has_text=False,
                raw_text="",
                spans=[],
                risk_score=0.0,
                confidence=text_conf,
                matched_signatures=[],
                latency_ms=0.0,
            )
        else:
            # Step 2B: Full Optical Character Recognition
            t_ocr_start = time.perf_counter()
            prep_img = preprocess_for_ocr(canonical_img)
            spans = self._ocr_engine.extract_spans(prep_img)
            raw_text = " ".join(s.text for s in spans).strip()
            ocr_latency = (time.perf_counter() - t_ocr_start) * 1000.0

            # Route extracted OCR text through Sentinel's existing Ingress pipeline
            text_risk = 0.0
            matched_sigs = []

            if raw_text:
                norm_text = normalize_text(raw_text)

                # Check Pattern Hunter
                p_res = self._pattern_hunter.scan(norm_text)
                p_score = float(p_res.get("score", 0.0))
                matched_sigs.extend(p_res.get("matched_signatures", []))

                # Check DeBERTa-v3 Semantic Analyst
                s_res = self._semantic_analyst.analyze(norm_text)
                s_score = float(s_res.get("score", 0.0))

                text_risk = max(p_score, s_score)

                # Check spans individually for localized injection markers
                for sp in spans:
                    sp_norm = normalize_text(sp.text)
                    sp_scan = self._pattern_hunter.scan(sp_norm)
                    if sp_scan.get("matched_signatures") or sp_scan.get("score", 0) >= 70.0:
                        sp.is_suspicious = True
                        sp.matched_patterns = sp_scan.get("matched_signatures", [])
                        suspicious_spans.append(sp)

            ocr_res = OCRAnalysisResult(
                backend=self._ocr_engine.name(),
                has_text=bool(raw_text),
                raw_text=raw_text,
                spans=spans,
                risk_score=round(text_risk, 2),
                confidence=round(text_conf, 2),
                matched_signatures=matched_sigs,
                latency_ms=round(ocr_latency, 2),
            )

        # Step 3: Semantic Concept Scoring (Zero-Text Jailbreaks)
        concept_res = concept_scorer.score_image(canonical_img)

        # Step 4: Spatial Rich Model (SRM) Adversarial Perturbation Detection
        noise_res = pgd_noise_detector.analyze_image(canonical_img)

        # Step 5: LSB Bit-Plane Chi-Square Steganalysis
        stego_res = lsb_stego_detector.analyze_image(canonical_img)

        # Step 6: Master Consensus Arbitration
        (
            composite_risk,
            verdict,
            policy_action,
            final_sigs,
            reasoning,
        ) = vision_judge.arbitrate(
            ocr_res=ocr_res,
            concept_res=concept_res,
            noise_res=noise_res,
            stego_res=stego_res,
            allow_redaction=allow_redaction,
        )

        # Step 7: Localized Redaction (if applicable)
        redacted_b64 = None
        if policy_action == VisionPolicyActionEnum.REDACT_IMAGE and suspicious_spans:
            boxes_to_mask = [s.box for s in suspicious_spans]
            _, redacted_b64 = image_redactor.redact_boxes(canonical_img, boxes_to_mask)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        result = VisionScanResult(
            sha256=img_sha256,
            filename=filename,
            width=canonical_img.width,
            height=canonical_img.height,
            format=meta.get("original_format", "PNG"),
            has_text=has_text,
            verdict=verdict,
            policy_action=policy_action,
            composite_risk_score=composite_risk,
            confidence=round(ocr_res.confidence, 2),
            scan_latency_ms=round(elapsed_ms, 2),
            ocr_analysis=ocr_res,
            concept_analysis=concept_res,
            noise_analysis=noise_res,
            stego_analysis=stego_res,
            matched_signatures=final_sigs,
            reasoning=reasoning,
            redacted_image_base64=redacted_b64,
            cached=False,
        )

        # Update LRU cache
        with self._cache_lock:
            if len(self._image_cache) >= self._cache_size:
                # Evict oldest
                first_key = next(iter(self._image_cache))
                del self._image_cache[first_key]
            self._image_cache[cache_key] = result

        # Release accelerator memory eagerly on M1 Apple Silicon / CUDA
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        elif hasattr(torch, "mps") and hasattr(torch.mps, "empty_cache"):
            try:
                torch.mps.empty_cache()
            except Exception:
                pass

        return result

    def scan_document(
        self,
        doc_bytes: bytes,
        filename: str = "document.pdf",
    ) -> DocScanResult:
        """
        Executes forensic structural inspection on PDF or DOCX documents.
        """
        start_time = time.perf_counter()
        doc_sha256 = hashlib.sha256(doc_bytes).hexdigest()

        with self._cache_lock:
            if doc_sha256 in self._doc_cache:
                cached = self._doc_cache[doc_sha256].model_copy()
                cached.cached = True
                cached.scan_latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                return cached

        # Detect document format
        is_pdf = doc_bytes.startswith(b"%PDF") or filename.lower().endswith(".pdf")
        is_docx = (
            doc_bytes.startswith(b"PK\x03\x04") or filename.lower().endswith(".docx")
        )

        try:
            if is_pdf:
                fmt = "PDF"
                pages, findings, text = pdf_threat_parser.parse_pdf_bytes(
                    doc_bytes,
                    scan_embedded_images=True,
                    vision_engine=self,
                )
            elif is_docx:
                fmt = "DOCX"
                pages, findings, text = docx_threat_parser.parse_docx_bytes(doc_bytes)
            else:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return DocScanResult(
                    sha256=doc_sha256,
                    filename=filename,
                    format="UNKNOWN",
                    total_pages=0,
                    composite_risk_score=90.0,
                    verdict=VisionVerdictEnum.CORRUPT_UNSCANNABLE,
                    policy_action=VisionPolicyActionEnum.BLOCK,
                    scan_latency_ms=round(elapsed_ms, 2),
                    reasoning="Unsupported document format (only PDF and DOCX are accepted).",
                )

            # Roll up page risks
            (
                composite_risk,
                verdict,
                policy_action,
                reasoning,
            ) = page_aggregator.aggregate(pages, findings)

            matched_sigs = [f"DOC:{f.rule_type}" for f in findings]

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            result = DocScanResult(
                sha256=doc_sha256,
                filename=filename,
                format=fmt,
                total_pages=len(pages),
                composite_risk_score=composite_risk,
                verdict=verdict,
                policy_action=policy_action,
                pages=pages,
                findings=findings,
                matched_signatures=list(set(matched_sigs)),
                scan_latency_ms=round(elapsed_ms, 2),
                reasoning=reasoning,
                cached=False,
            )

            with self._cache_lock:
                if len(self._doc_cache) >= self._cache_size:
                    first_key = next(iter(self._doc_cache))
                    del self._doc_cache[first_key]
                self._doc_cache[doc_sha256] = result

            return result

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DocScanResult(
                sha256=doc_sha256,
                filename=filename,
                format="UNKNOWN",
                total_pages=0,
                composite_risk_score=95.0,
                verdict=VisionVerdictEnum.CORRUPT_UNSCANNABLE,
                policy_action=VisionPolicyActionEnum.BLOCK,
                scan_latency_ms=round(elapsed_ms, 2),
                reasoning=f"Document parsing error: {str(e)}",
            )


# Global singleton vision engine coordinator
vision_engine = VisionEngine()
