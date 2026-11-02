"""
EasyOCR Backend Driver (Pillar III)
Pure PyTorch optical character recognition engine with Apple Silicon (MPS) and CUDA support.
"""

from typing import List, Optional
import numpy as np
from PIL import Image
import torch

from core.vision.ocr.base import OCREngine
from core.vision.schemas import OCRSpan, BoundingBox


class EasyOCRDriver(OCREngine):
    """
    Primary OCR driver leveraging EasyOCR (pure PyTorch).
    Handles rotated and low-contrast typography with high accuracy.
    """

    def __init__(self):
        self._reader = None
        self._initialized = False

    def is_available(self) -> bool:
        try:
            import easyocr
            return True
        except ImportError:
            return False

    def name(self) -> str:
        return "easyocr"

    def _ensure_reader(self):
        if self._initialized:
            return
        import easyocr
        use_gpu = torch.backends.mps.is_available() or torch.cuda.is_available()
        # Initialize English recognition
        self._reader = easyocr.Reader(["en"], gpu=use_gpu, verbose=False)
        self._initialized = True

    def extract_spans(self, img: Image.Image) -> List[OCRSpan]:
        if not self.is_available():
            return []

        self._ensure_reader()
        arr = np.array(img)
        w, h = img.size

        # EasyOCR returns list of (bbox, text, prob)
        # where bbox is [[x1, y1], [x2, y1], [x2, y2], [x1, y2]]
        results = self._reader.readtext(arr)
        spans = []

        for bbox_coords, text, prob in results:
            clean_text = text.strip()
            if not clean_text:
                continue

            xs = [pt[0] for pt in bbox_coords]
            ys = [pt[1] for pt in bbox_coords]
            min_x, max_x = max(0, min(xs)), min(w, max(xs))
            min_y, max_y = max(0, min(ys)), min(h, max(ys))

            norm_box = BoundingBox(
                x1=round(min_x / max(1, w), 4),
                y1=round(min_y / max(1, h), 4),
                x2=round(max_x / max(1, w), 4),
                y2=round(max_y / max(1, h), 4),
                is_normalized=True,
            )

            spans.append(
                OCRSpan(
                    text=clean_text,
                    box=norm_box,
                    confidence=round(float(prob), 4),
                )
            )

        return spans

