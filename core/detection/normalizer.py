import re
import unicodedata

# 1. Regex to strip invisible, zero-width, tag, bidi control, and formatting characters
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
    "А": "A", "В": "B", "С": "C", "Ε": "E", "Н": "H", "І": "I",
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

# 3. Colloquial slang and adversarial typo normalizations (compiled word boundaries)
_SLANG_AND_TYPOS = [
    (re.compile(r"\bur\b", re.IGNORECASE), "your"),
    (re.compile(r"\bu\b", re.IGNORECASE), "you"),
    (re.compile(r"\br\b", re.IGNORECASE), "are"),
    (re.compile(r"\bpls\b|\bplz\b", re.IGNORECASE), "please"),
    (re.compile(r"\bsorce\b", re.IGNORECASE), "source"),
    (re.compile(r"\bpromptt\b", re.IGNORECASE), "prompt"),
    (re.compile(r"\binstuctions?\b|\binstructins?\b", re.IGNORECASE), "instructions"),
    (re.compile(r"\bjailbrek\b|\bjailbrak\b", re.IGNORECASE), "jailbreak"),
    (re.compile(r"\bbyepass\b|\bby-pass\b", re.IGNORECASE), "bypass"),
    (re.compile(r"\bdisreguard\b", re.IGNORECASE), "disregard"),
]

# Repeated character collapse pattern (e.g. "soooource" -> "source")
_REPEATED_CHARS_RE = re.compile(r"(.)\1{2,}")


def normalize_text(text: str) -> str:
    """
    Normalizes text for security inspection without mutating the original user payload.
    
    Pipeline:
    1. Strip invisible, zero-width, bidi, and tag characters.
    2. Apply Unicode NFKC normalization (decomposes ligatures, converts fullwidth & math styles).
    3. Skeletonize high-risk Cyrillic and Greek homoglyphs to Latin equivalents.
    4. Collapse excessive character repetitions (e.g., 'soooource' -> 'source').
    5. Expand high-risk colloquial slang and spelling errors ('ur sorce code' -> 'your source code').
    6. Normalize whitespace sequences.
    """
    if not text:
        return ""

    # Step 1: Strip zero-width, invisible, and bidi override characters
    cleaned = _INVISIBLE_AND_BIDI_RE.sub("", text)

    # Step 2: Unicode NFKC decomposition & compatibility folding
    decomposed = unicodedata.normalize("NFKC", cleaned)

    # Step 3: Homoglyph skeletonization
    skeletonized = decomposed.translate(_HOMOGLYPH_TRANS)

    # Step 4: Collapse repeated characters (3+ repeated -> 1 or 2)
    collapsed = _REPEATED_CHARS_RE.sub(r"\1\1", skeletonized)

    # Step 5: Expand slang and canonicalize common evasion typos
    normalized = collapsed
    for regex, replacement in _SLANG_AND_TYPOS:
        normalized = regex.sub(replacement, normalized)

    # Step 6: Collapse whitespace
    normalized = " ".join(normalized.split())

    return normalized.strip()
