"""
Configuration and Tuning Parameters for Pillar III Vision & Document Threat Engine
Defines thresholds, hardware auto-discovery, safety bounds, and fail-safe defaults.
"""

import os
import torch

# ── Hardware & Execution Environment ──────────────────────────────────────────
def get_optimal_device() -> torch.device:
    """Auto-detects Apple Silicon Metal (MPS), NVIDIA CUDA, or CPU."""
    if torch.backends.mps.is_available() and torch.backends.mps.is_built():
        return torch.device("mps")
    elif torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")

DEVICE = get_optimal_device()

# ── Resource & Decompression Bomb Safety Caps ──────────────────────────────────
MAX_IMAGE_FILE_BYTES = 32 * 1024 * 1024  # 32 MB streaming chunked cap
MAX_IMAGE_PIXELS = 16_000_000             # 16 Megapixels max (Strict M1 Air memory safety limit)
MAX_DOC_PAGES = 100                       # Maximum document pages scanned before fail-closed quarantine
SCAN_TIMEOUT_SECONDS = 10.0               # Maximum seconds per end-to-end scan
DEFAULT_LRU_CACHE_SIZE = 512              # SHA-256 result cache capacity

# ── Two-Stage Text Presence Fast-Path ─────────────────────────────────────────
# Fractional threshold of high-gradient blocks (8x8) required to invoke OCR
TEXT_PRESENCE_GRADIENT_THRESHOLD = 0.012
TEXT_PRESENCE_VARIANCE_THRESHOLD = 15.0

# ── MobileCLIP-S0 Concept Margin Thresholds ────────────────────────────────────
# Margin = cos(img, threat_concept) - max(cos(img, benign_anchors))
CONCEPT_MARGIN_FLOOR = 0.04               # Margins <= 0.04 yield 0.0 risk
CONCEPT_MARGIN_CEILING = 0.22             # Margins >= 0.22 yield 100.0 risk
CONCEPT_SOLO_CERTAINTY_THRESHOLD = 92.0   # Extremely high confidence alone can trigger block

# ── Spatial Rich Model (SRM) & Adversarial Noise ──────────────────────────────
SRM_QUANTIZATION_TRUNCATION_T = 3.0       # Standard steganalysis residual clipping [-T, T]
EDGE_RESIDUAL_CORRELATION_THRESHOLD = 0.45 # Natural text >= 0.50; PGD perturbations < 0.40
FLAT_REGION_LEAKAGE_THRESHOLD = 3.2       # High residual energy in flat whitespace indicates PGD noise
LSB_CHI_SQUARE_MIN_POVS = 4000            # Minimum Pairs of Values to evaluate chi-square
LSB_CHI_SQUARE_P_THRESHOLD = 0.999        # P-value indicating artificial LSB bitplane equalization

# ── Document Hidden-Text Thresholds ───────────────────────────────────────────
MAX_MICRO_FONT_SIZE_PT = 1.8              # Absolute font size in points (after CTM scaling)
RELATIVE_MICRO_FONT_RATIO = 0.15          # Relative to page median font size
DELTA_E_PERCEPTUAL_THRESHOLD = 4.5        # CIE Delta E 2000 perceptual threshold (imperceptible text)
MIN_HIDDEN_TEXT_CHAR_COUNT = 8            # Minimum character length to trigger hidden-text alert
MAX_PLUS_MEAN_PAGE_WEIGHT = 0.15          # Asymmetric page rollup weight for multi-page documents

# ── Consensus Arbitration Tiers ───────────────────────────────────────────────
RISK_THRESHOLD_ALLOW = 40.0               # Below 40.0: ALLOW
RISK_THRESHOLD_FLAG = 75.0                # 40.0 to 74.9: FLAG (Allowed & Monitored)
RISK_THRESHOLD_BLOCK = 75.0               # 75.0 and above: BLOCK (HTTP 403)
SOLO_SOFT_CHANNEL_MAX_SCORE = 74.0        # Uncorroborated single soft signal is clamped at FLAG

# ── Redaction Configuration ───────────────────────────────────────────────────
REDACTION_MASK_COLOR = (24, 24, 24)       # Neutral dark charcoal solid mask (RGB)
REDACTION_MASK_PADDING_PX = 6             # Spatial box dilation to prevent descender leakage
REDACTION_STAMP_TEXT = "[REDACTED: POLICY VIOLATION]"

# ── OCR Backend Selection ─────────────────────────────────────────────────────
# "auto" probes EasyOCR -> Tesseract -> MockOCRDriver
# Can be overridden via environment variables VISION_OCR_BACKEND or SENTINEL_OCR_BACKEND
OCR_BACKEND_OVERRIDE = (
    os.environ.get("VISION_OCR_BACKEND") or os.environ.get("SENTINEL_OCR_BACKEND", "auto")
).lower()
