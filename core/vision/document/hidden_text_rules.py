"""
Document Hidden-Text Threat Rules (Pillar III)
Detects structural stealth techniques in PDFs and DOCX files:
1. Render Mode 3 (PDF transparent text layer).
2. Perceptual color distance Delta E <= 4.5 (white-on-white text).
3. Microscopic typography <= 1.8pt.
4. Off-canvas coordinates outside visible CropBox.
5. OOXML <w:vanish> hidden-run flags.
"""

import math
from typing import Tuple, List, Optional
from core.vision.schemas import DocHiddenTextFinding, BoundingBox
from core.vision.config import (
    MAX_MICRO_FONT_SIZE_PT,
    RELATIVE_MICRO_FONT_RATIO,
    DELTA_E_PERCEPTUAL_THRESHOLD,
    MIN_HIDDEN_TEXT_CHAR_COUNT,
)


def rgb_to_cielab(rgb: Tuple[int, int, int]) -> Tuple[float, float, float]:
    """
    Converts 8-bit sRGB (0-255) to CIE L*a*b* color space via standard D65 illuminant.
    """
    r, g, b = [x / 255.0 for x in rgb]

    # Inverse sRGB companding
    r = ((r + 0.055) / 1.055) ** 2.4 if r > 0.04045 else r / 12.92
    g = ((g + 0.055) / 1.055) ** 2.4 if g > 0.04045 else g / 12.92
    b = ((b + 0.055) / 1.055) ** 2.4 if b > 0.04045 else b / 12.92

    # Linear RGB to XYZ (D65)
    x = r * 0.4124564 + g * 0.3575761 + b * 0.1804375
    y = r * 0.2126729 + g * 0.7151522 + b * 0.0721750
    z = r * 0.0193339 + g * 0.1191920 + b * 0.9503041

    # Normalize for D65 white point: (0.95047, 1.00000, 1.08883)
    x /= 0.95047
    y /= 1.00000
    z /= 1.08883

    # Non-linear XYZ to Lab mapping
    delta = 6.0 / 29.0
    fx = x ** (1.0 / 3.0) if x > delta**3 else (x / (3 * delta**2)) + (4.0 / 29.0)
    fy = y ** (1.0 / 3.0) if y > delta**3 else (y / (3 * delta**2)) + (4.0 / 29.0)
    fz = z ** (1.0 / 3.0) if z > delta**3 else (z / (3 * delta**2)) + (4.0 / 29.0)

    l_star = max(0.0, min(100.0, 116.0 * fy - 16.0))
    a_star = 500.0 * (fx - fy)
    b_star = 200.0 * (fy - fz)

    return l_star, a_star, b_star


def compute_delta_e_cie76(rgb1: Tuple[int, int, int], rgb2: Tuple[int, int, int]) -> float:
    """
    Computes standard Euclidean CIE Delta E distance in Lab color space.
    Delta E <= 4.5 indicates colors that are imperceptible or nearly indistinguishable to human vision.
    """
    l1, a1, b1 = rgb_to_cielab(rgb1)
    l2, a2, b2 = rgb_to_cielab(rgb2)
    return math.sqrt((l1 - l2) ** 2 + (a1 - a2) ** 2 + (b1 - b2) ** 2)


def is_micro_font(effective_font_size: float, page_median_font: float) -> bool:
    """
    Checks if a rendered font size is microscopic:
    - Absolute: effective_font_size <= 1.8pt.
    - Relative: effective_font_size < 0.15 * page_median_font (when median >= 10pt).
    """
    if effective_font_size <= MAX_MICRO_FONT_SIZE_PT:
        return True
    if page_median_font >= 10.0 and effective_font_size < (page_median_font * RELATIVE_MICRO_FONT_RATIO):
        return True
    return False


def is_off_canvas(box: BoundingBox, page_w: float, page_h: float) -> bool:
    """
    Checks if span bounding box falls entirely outside the visible page boundary.
    """
    x1, y1, x2, y2 = box.x1, box.y1, box.x2, box.y2
    # Zero intersection with [0, 0, page_w, page_h]
    if x2 <= 0 or x1 >= page_w or y2 <= 0 or y1 >= page_h:
        return True
    return False


def evaluate_span_security(
    text: str,
    font_size: float,
    ctm_scale: float,
    font_rgb: Tuple[int, int, int],
    bg_rgb: Tuple[int, int, int],
    render_mode: int,
    box: BoundingBox,
    page_w: float,
    page_h: float,
    page_median_font: float,
    page_num: int,
) -> List[DocHiddenTextFinding]:
    """
    Evaluates all hidden text threat rules on an extracted text span.
    """
    clean_text = text.strip()
    if len(clean_text) < MIN_HIDDEN_TEXT_CHAR_COUNT:
        return []

    findings: List[DocHiddenTextFinding] = []
    effective_font_size = font_size * ctm_scale

    # 1. Microscopic Font Rule
    if is_micro_font(effective_font_size, page_median_font):
        findings.append(
            DocHiddenTextFinding(
                page_num=page_num,
                rule_type="MICRO_FONT",
                text=clean_text[:120],
                font_size=round(font_size, 2),
                effective_font_size=round(effective_font_size, 2),
                box=box,
                severity="HIGH",
            )
        )

    # 2. Perceptual Color Distance Rule (White-on-White / Low-Contrast)
    delta_e = compute_delta_e_cie76(font_rgb, bg_rgb)
    if delta_e <= DELTA_E_PERCEPTUAL_THRESHOLD:
        findings.append(
            DocHiddenTextFinding(
                page_num=page_num,
                rule_type="COLOR_DISTANCE",
                text=clean_text[:120],
                font_size=round(font_size, 2),
                effective_font_size=round(effective_font_size, 2),
                delta_e=round(delta_e, 2),
                box=box,
                severity="CRITICAL",
            )
        )

    # 3. Off-Canvas Coordinate Rule
    if is_off_canvas(box, page_w, page_h):
        findings.append(
            DocHiddenTextFinding(
                page_num=page_num,
                rule_type="OFF_CANVAS",
                text=clean_text[:120],
                font_size=round(font_size, 2),
                effective_font_size=round(effective_font_size, 2),
                box=box,
                severity="HIGH",
            )
        )

    # 4. Render Mode 3 (Neither fill nor stroke - Transparent Text Layer)
    if render_mode == 3:
        findings.append(
            DocHiddenTextFinding(
                page_num=page_num,
                rule_type="RENDER_MODE_3",
                text=clean_text[:120],
                font_size=round(font_size, 2),
                effective_font_size=round(effective_font_size, 2),
                box=box,
                severity="MEDIUM",
            )
        )

    return findings

