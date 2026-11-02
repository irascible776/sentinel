"""
Tesseract OCR Driver (Pillar III)
Fast CPU pre-filter OCR driver utilizing pytesseract and system binary.
"""

import shutil
from typing import List
from PIL import Image

from core.vision.ocr.base import OCREngine
from core.vision.schemas import OCRSpan, BoundingBox


class TesseractDriver(OCREngine):
    """
    Secondary OCR driver using Tesseract C-binary.
    High-speed on plain text documents where tesseract is installed.
    """

    def is_available(self) -> bool:
        try:
            import pytesseract
            has_binary = shutil.which("tesseract") is not None
            return bool(has_binary)
        except ImportError:
            return False

    def name(self) -> str:
        return "tesseract"

    def extract_spans(self, img: Image.Image) -> List[OCRSpan]:
        if not self.is_available():
            return []

        import pytesseract
        from pytesseract import Output

        w, h = img.size
        try:
            data = pytesseract.image_to_data(img, output_type=Output.DICT)
        except Exception:
            return []

        n_boxes = len(data["text"])
        spans = []

        for i in range(n_boxes):
            text = (data["text"][i] or "").strip()
            conf = float(data["conf"][i])
            if conf <= 0 or not text:
                continue

            x = data["left"][i]
            y = data["top"][i]
            bw = data["width"][i]
            bh = data["height"][i]

            norm_box = BoundingBox(
                x1=round(max(0, x) / max(1, w), 4),
                y1=round(max(0, y) / max(1, h), 4),
                x2=round(min(w, x + bw) / max(1, w), 4),
                y2=round(min(h, y + bh) / max(1, h), 4),
                is_normalized=True,
            )

            spans.append(
                OCRSpan(
                    text=text,
                    box=norm_box,
                    confidence=round(conf / 100.0, 4),
                )
            )

        return spans

