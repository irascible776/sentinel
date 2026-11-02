"""
Solid-Mask Image Redaction Engine (Pillar III)
Applies non-reversible solid opaque masks over detected visual injection bounding boxes.
Rebuilds images cleanly from decoded pixels to prevent information leakage or deconvolution attacks.
"""

import io
import base64
from typing import List, Tuple, Optional
from PIL import Image, ImageDraw, ImageFont

from core.vision.schemas import BoundingBox
from core.vision.config import (
    REDACTION_MASK_COLOR,
    REDACTION_MASK_PADDING_PX,
    REDACTION_STAMP_TEXT,
)


class ImageRedactor:
    """
    Spatially localized image sanitizer.
    Replaces threatening text or visual regions with an opaque charcoal rectangle and audit watermark.
    """

    def __init__(
        self,
        mask_color: Tuple[int, int, int] = REDACTION_MASK_COLOR,
        padding_px: int = REDACTION_MASK_PADDING_PX,
        stamp_text: str = REDACTION_STAMP_TEXT,
    ):
        self.mask_color = mask_color
        self.padding_px = padding_px
        self.stamp_text = stamp_text

    def redact_boxes(
        self,
        img: Image.Image,
        boxes: List[BoundingBox],
    ) -> Tuple[Image.Image, str]:
        """
        Applies solid masks over specified bounding boxes.

        Returns:
            (redacted_pil_image, base64_png_string)
        """
        if not boxes:
            out_buf = io.BytesIO()
            img.save(out_buf, format="PNG")
            b64_str = base64.b64encode(out_buf.getvalue()).decode("utf-8")
            return img.copy(), b64_str

        # Clone image to avoid mutating original
        redacted = img.copy().convert("RGB")
        draw = ImageDraw.Draw(redacted)
        w, h = redacted.size

        for box in boxes:
            x1, y1, x2, y2 = box.to_pixel_box(w, h)

            # Apply spatial dilation padding to prevent descender or edge-glyph leakage
            px1 = max(0, x1 - self.padding_px)
            py1 = max(0, y1 - self.padding_px)
            px2 = min(w, x2 + self.padding_px)
            py2 = min(h, y2 + self.padding_px)

            # Draw solid opaque mask
            draw.rectangle([px1, py1, px2, py2], fill=self.mask_color)

            # Add audit watermark text if box is sufficiently large
            box_w = px2 - px1
            box_h = py2 - py1
            if box_w >= 120 and box_h >= 16:
                text_x = px1 + 6
                text_y = py1 + max(2, (box_h - 12) // 2)
                # Subtle light-gray audit text on dark charcoal mask
                draw.text(
                    (text_x, text_y),
                    self.stamp_text,
                    fill=(200, 200, 200),
                )

        # Re-encode clean sanitized PNG bytes
        out_buf = io.BytesIO()
        redacted.save(out_buf, format="PNG", optimize=True)
        canonical_bytes = out_buf.getvalue()
        b64_str = base64.b64encode(canonical_bytes).decode("utf-8")

        return redacted, b64_str


# Global redactor instance
image_redactor = ImageRedactor()

