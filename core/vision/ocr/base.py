"""
Abstract Base Class for OCR Backends (Pillar III)
Defines the standard contract for optical character recognition engines.
"""

from abc import ABC, abstractmethod
from typing import List
from PIL import Image

from core.vision.schemas import OCRSpan


class OCREngine(ABC):
    """
    Abstract interface for optical character recognition engines.
    Implementations must extract text spans with bounding boxes and confidence scores.
    """

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the backend dependencies (libraries/binaries) are accessible."""
        pass

    @abstractmethod
    def name(self) -> str:
        """Returns the unique identifier of the OCR backend."""
        pass

    @abstractmethod
    def extract_spans(self, img: Image.Image) -> List[OCRSpan]:
        """
        Extracts all textual bounding spans from a canonical PIL Image.
        Returns a list of OCRSpan instances with normalized [0.0 - 1.0] bounding boxes.
        """
        pass

