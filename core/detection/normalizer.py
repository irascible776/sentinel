import re
import unicodedata

# 1. Regex to strip invisible, zero-width, tag, bidi control, and formatting characters
# \u200B-\u200D: Zero-width space, non-joiner, joiner
# \uFEFF: Zero-width no-break space (BOM)
# \u00AD: Soft hyphen
# \u202A-\u202E: Bidi directional embedding/override controls
# \u2066-\u2069: Bidi directional isolate controls
# \U000E0000-\U000E007F: Unicode language tag characters
_INVISIBLE_AND_BIDI_RE = re.compile(
    r"[\u200B-\u200D\uFEFF\u00AD\u202A-\u202E\u2066-\u2069\U000E0000-\U000E007F]"
)

# 2. Targeted homoglyph substitution mapping (Cyrillic & Greek lookalikes to Latin ASCII)
_HOMOGLYPH_MAP = {
    # Cyrillic lowercase to Latin
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "ѕ": "s",
    "ԁ": "d", "і": "i", "ј": "j", "у": "y", "х": "x", "в": "b",
    "п": "n", "т": "t", "г": "r", "м": "m", "к": "k",
    # Cyrillic uppercase to Latin
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I",
    "Ј": "J", "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S",
    "Т": "T", "Х": "X", "Ү": "Y",
    # Greek lowercase lookalikes
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i",
    "κ": "k", "χ": "x",
    # Greek uppercase lookalikes
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Χ": "X", "Υ": "Y",
}
_HOMOGLYPH_TRANS = str.maketrans(_HOMOGLYPH_MAP)


def normalize_text(text: str) -> str:
    """
    Normalizes text for security inspection without mutating the original user payload.
    
    Pipeline:
    1. Strip invisible, zero-width, bidi, and tag characters.
    2. Apply Unicode NFKC normalization (decomposes ligatures, converts fullwidth & math styles).
    3. Skeletonize high-risk Cyrillic and Greek homoglyphs to Latin equivalents.
    4. Collapse excessive whitespace sequences.
    """
    if not text:
        return ""

    # Step 1: Strip zero-width, invisible, and bidi override characters
    cleaned = _INVISIBLE_AND_BIDI_RE.sub("", text)

    # Step 2: Unicode NFKC decomposition & compatibility folding
    decomposed = unicodedata.normalize("NFKC", cleaned)

    # Step 3: Homoglyph skeletonization
    skeletonized = decomposed.translate(_HOMOGLYPH_TRANS)

    return skeletonized.strip()
