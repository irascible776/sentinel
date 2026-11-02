"""
OCR Engine Factory with Capability Probing (Pillar III)
Dynamically selects the optimal available OCR backend (EasyOCR -> Tesseract -> Mock)
based on environment capability probing and configuration overrides.
"""

import os
from typing import Optional
from core.vision.ocr.base import OCREngine
from core.vision.ocr.easyocr_driver import EasyOCRDriver
from core.vision.ocr.tesseract_driver import TesseractDriver
from core.vision.ocr.mock_driver import MockOCRDriver
from core.vision.config import OCR_BACKEND_OVERRIDE


class OCRFactory:
    """
    Factory with resilient capability probing.
    Ensures zero runtime crashes if an OCR driver library is missing.
    """

    _cached_engine: Optional[OCREngine] = None

    @classmethod
    def get_engine(cls, override_backend: Optional[str] = None) -> OCREngine:
        """
        Returns the appropriate OCR engine based on environment and availability.
        Priority: Parameter Override -> Config / Env Override -> EasyOCR -> Tesseract -> Mock.
        """
        if override_backend is None and cls._cached_engine is not None:
            return cls._cached_engine

        target = (override_backend or OCR_BACKEND_OVERRIDE).lower()

        if target == "mock" or os.environ.get("SENTINEL_TEST_MODE") == "1":
            engine = MockOCRDriver()
            if override_backend is None:
                cls._cached_engine = engine
            return engine

        if target == "easyocr":
            easy = EasyOCRDriver()
            if easy.is_available():
                if override_backend is None:
                    cls._cached_engine = easy
                return easy
            # Fallback if requested explicitly but missing

        if target == "tesseract":
            tess = TesseractDriver()
            if tess.is_available():
                if override_backend is None:
                    cls._cached_engine = tess
                return tess
            # Fallback if requested explicitly but missing

        # Auto capability probing
        easy = EasyOCRDriver()
        if easy.is_available():
            if override_backend is None:
                cls._cached_engine = easy
            return easy

        tess = TesseractDriver()
        if tess.is_available():
            if override_backend is None:
                cls._cached_engine = tess
            return tess

        # Final deterministic fallback for CI and headless environments
        engine = MockOCRDriver()
        if override_backend is None:
            cls._cached_engine = engine
        return engine


# Global default OCR factory instance
default_ocr_engine = OCRFactory.get_engine()
