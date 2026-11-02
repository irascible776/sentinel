"""
Developer 1 (Rohit Verma) — Channel B: Application-Harm Intent Classifier
Detects malicious application-plane requests: malware, ransomware, phishing,
exploit generation, keyloggers. Completely independent from Channel A (DeBERTa
prompt injection detection). Runs in parallel with Channel A.

Primary Layer  : Weighted Keyword Intent Scoring   (<1ms,  no dependencies)
Secondary Layer: DistilBERT/MiniLM Safety Classifier (~15ms, optional if model present)

Model source: protectai/deberta-v3-base-prompt-injection-v2 or
              custom harm classifier in sentinel/models/channel_b_intent/
              (See scripts/download_models.py to fetch)
"""

import os
import time
import re
from typing import Dict, Any, Optional, List

# ──────────────────────────────────────────────────────────────────────────────
# Cyber-Harm Keyword Taxonomy  (term → base_weight, higher = more dangerous)
# Organised as a trie-like group for readability and easy extension.
# ──────────────────────────────────────────────────────────────────────────────
HARM_TAXONOMY: List[Dict[str, Any]] = [
    # ── MALWARE / KEYLOGGERS ──────────────────────────────────────────────────
    {"terms": ["keylogger", "key logger", "keystroke logger", "keystroke capture",
               "keyboard hook", "keyboard logger", "keyboard spy"],
     "category": "MALWARE", "weight": 90},
    {"terms": ["spyware", "stalkerware", "screen grabber malware",
               "credential stealer", "credential harvester", "password stealer"],
     "category": "MALWARE", "weight": 88},
    {"terms": ["ransomware", "file encryptor", "ransom note", "ransom payload",
               "file locker", "crypto locker"],
     "category": "MALWARE", "weight": 92},
    {"terms": ["trojan", "rootkit", "bootkit", "malware dropper", "malware loader",
               "malware stager", "payload stager", "dropper payload"],
     "category": "MALWARE", "weight": 90},
    {"terms": ["c2 beacon", "c&c beacon", "command and control beacon",
               "command-and-control client", "rat payload", "rat client",
               "remote access trojan", "backdoor malware"],
     "category": "MALWARE", "weight": 93},
    {"terms": ["conversation intercept", "conversations with other people", "conversations with other poeple",
               "chat monitor", "spy on conversations", "intercept conversations",
               "eavesdropping tool", "silent listener", "secretly monitor", "surveillance tool",
               "background spy", "stalking tool", "runs in background and responds",
               "responds to users conversations", "tool that runs in background"],
     "category": "SURVEILLANCE", "weight": 86},
    {"terms": ["session hijacking", "session hijack", "cookie theft", "cookie stealer",
               "dump cookies", "browser cookies", "steal cookies", "cookie exfiltration",
               "session cookies", "authentication tokens", "token extraction", "relay to webhook",
               "credential dumping", "memory dump password", "token stealer",
               "data exfiltration", "exfiltrate data", "exfiltrate over", "exfiltration script"],
     "category": "CREDENTIAL_THEFT", "weight": 89},

    # ── PHISHING / SOCIAL ENGINEERING ────────────────────────────────────────
    {"terms": ["phishing email", "phishing page", "phishing site", "phishing template",
               "phishing kit", "credential harvesting form", "credential capture page",
               "fake login page", "fake bank page", "spear phishing",
               "smishing template", "vishing script"],
     "category": "PHISHING", "weight": 88},

    # ── EXPLOITS / SHELLS ─────────────────────────────────────────────────────
    {"terms": ["reverse shell", "bind shell", "meterpreter payload",
               "meterpreter stager", "shellcode", "shellcode payload",
               "buffer overflow exploit", "heap spray", "rop chain",
               "privilege escalation script", "privilege escalation exploit",
               "local privilege escalation", "lpe exploit"],
     "category": "EXPLOIT", "weight": 91},
    {"terms": ["remote code execution exploit", "rce exploit", "cve exploit",
               "exploit for cve", "0day exploit", "zero-day payload"],
     "category": "EXPLOIT", "weight": 93},
    {"terms": ["sql injection payload", "sqli payload", "xss payload steal",
               "csrf token theft", "ssrf exploit", "xxe payload",
               "deserialization exploit"],
     "category": "EXPLOIT", "weight": 82},

    # ── NETWORK ATTACKS ───────────────────────────────────────────────────────
    {"terms": ["ddos tool", "ddos script", "ddos bot", "syn flood script",
               "udp flood tool", "slowloris attack", "http flood",
               "botnet client", "botnet controller", "mirai bot"],
     "category": "NETWORK_ATTACK", "weight": 87},

    # ── DUAL-USE FLAGGED (educational discount applied via context) ───────────
    # These carry lower weights — the Arbiter + Artifact Test decides final verdict.
    {"terms": ["port scanner", "network scanner", "vulnerability scanner",
               "password cracker", "hash cracker", "brute force script"],
     "category": "DUAL_USE", "weight": 55},
    {"terms": ["packet sniffer", "arp spoof", "dns spoof", "man in the middle",
               "mitm script", "traffic intercept"],
     "category": "DUAL_USE", "weight": 58},
]

# ──────────────────────────────────────────────────────────────────────────────
# Action Amplifiers: presence of explicit "write me" / "build" intent
# significantly raises the score vs. purely academic "explain" context.
# ──────────────────────────────────────────────────────────────────────────────
ACTION_AMPLIFIERS = re.compile(
    r"(?i)\b(write|create|build|code|make|develop|generate|implement|script|give\s+me|"
    r"produce|output|design)\b"
)

DEFENSIVE_DISCOUNTS = re.compile(
    r"(?i)\b(detect|prevent|defend|protect|patch|mitigate|analyze|signature(\s+for)?|"
    r"how\s+does\s+.{0,30}\s+work|explain\s+how|educational|study|research)\b"
)

FICTIONAL_DISCOUNT = re.compile(
    r"(?i)\b(in\s+a\s+(movie|book|story|novel|game)|fictional|hypothetically|"
    r"for\s+a\s+ctf\s+challenge|capture\s+the\s+flag)\b"
)


class IntentClassifier:
    """
    Channel B: Application-Harm Intent Classifier.

    Detects malicious application-plane requests that bypass Control-Plane
    (prompt injection) models entirely. Completely stateless and independent
    from the DeBERTa Semantic Analyst (Channel A).

    Scoring:
        0.0  – 34.9 : CLEAN  (forward to LLM)
        35.0 – 74.9 : GRAY   (escalate to Stage 2 Arbiter)
        75.0 – 100.0: BLOCK  (direct block, no arbiter needed)
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        device: Optional[str] = None
    ):
        # Resolve optional transformer model path
        if model_path is None:
            model_path = os.getenv("INTENT_MODEL_PATH")
            if not model_path:
                # Default: look for downloaded model next to sentinel_deberta
                candidate = os.path.join(
                    os.path.dirname(__file__), "../../models/channel_b_intent"
                )
                if os.path.exists(os.path.abspath(candidate)):
                    model_path = os.path.abspath(candidate)

        self.model_path = model_path
        # Determine device: cuda > mps (Apple Silicon Metal) > cpu
        if device is None:
            configured_device = os.getenv("DETECTION_DEVICE", "auto").lower()
            if configured_device == "cuda":
                device = "cuda"
            elif configured_device == "mps":
                device = "mps"
            else:
                # Auto-detect: use Apple Metal GPU if available (M1/M2/M3 Mac)
                try:
                    import torch
                    if torch.backends.mps.is_available():
                        device = "mps"
                    else:
                        device = "cpu"
                except Exception:
                    device = "cpu"
        self.device = device
        self._classifier = None
        self._model_load_failed = False

        # Pre-compile taxonomy patterns for O(n) lookup
        self._compiled_taxonomy: List[Dict[str, Any]] = []
        for entry in HARM_TAXONOMY:
            patterns = []
            for term in entry["terms"]:
                patterns.append(re.compile(
                    r"(?i)\b" + re.escape(term) + r"\b"
                ))
            self._compiled_taxonomy.append({
                **entry,
                "_compiled": patterns
            })

    # ──────────────────────────────────────────────────────────────────────────
    # Optional Transformer Model (secondary, for gray-zone ambiguity)
    # ──────────────────────────────────────────────────────────────────────────
    def _load_model(self):
        """Lazy-loads optional HuggingFace harm classifier."""
        if self._classifier is not None or self._model_load_failed:
            return
        if not self.model_path or not os.path.exists(self.model_path):
            self._model_load_failed = True
            return
        try:
            from transformers import pipeline
            self._classifier = pipeline(
                "text-classification",
                model=self.model_path,
                device=self.device,
                truncation=True,
                max_length=512
            )
        except Exception:
            self._model_load_failed = True

    # ──────────────────────────────────────────────────────────────────────────
    # Core Keyword Scoring (always runs, <1ms)
    # ──────────────────────────────────────────────────────────────────────────
    def _keyword_score(self, prompt: str) -> Dict[str, Any]:
        """
        Fast keyword-weighted scoring. Returns a score, matched category,
        and matched terms for transparency.
        """
        lower = prompt.lower()
        max_weight = 0.0
        matched_category = "NONE"
        matched_terms: List[str] = []

        for entry in self._compiled_taxonomy:
            for i, pattern in enumerate(entry["_compiled"]):
                if pattern.search(lower):
                    term = entry["terms"][i]
                    weight = float(entry["weight"])
                    matched_terms.append(term)

                    # Action Amplifier: explicit write/build intent → boost score
                    if ACTION_AMPLIFIERS.search(prompt):
                        weight = min(100.0, weight * 1.08)
                    else:
                        # No explicit write intent — may be asking to understand/explain
                        weight *= 0.70

                    # Defensive context discount
                    if DEFENSIVE_DISCOUNTS.search(prompt):
                        weight *= 0.50

                    # Fictional framing discount (still flagged for Arbiter review)
                    if FICTIONAL_DISCOUNT.search(prompt):
                        weight = min(weight, 65.0)

                    if weight > max_weight:
                        max_weight = weight
                        matched_category = entry["category"]

        return {
            "score": round(min(100.0, max_weight), 2),
            "category": matched_category,
            "matched_terms": matched_terms,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Optional Transformer Inference (secondary, runs if model is available)
    # ──────────────────────────────────────────────────────────────────────────
    def _transformer_score(self, prompt: str) -> Optional[float]:
        """Returns transformer-based harm probability [0.0, 100.0] or None."""
        self._load_model()
        if self._classifier is None:
            return None
        try:
            truncated = prompt[:2000]
            raw = self._classifier(truncated)
            pred = raw[0]
            label = pred.get("label", "").upper()
            prob = float(pred.get("score", 0.5))
            # Assumes LABEL_1 = harmful, LABEL_0 = benign
            is_harmful = label in ["LABEL_1", "HARMFUL", "UNSAFE"] or "HARM" in label
            return round((prob if is_harmful else 1.0 - prob) * 100.0, 2)
        except Exception:
            return None

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────
    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Runs Channel B harm intent analysis on a user prompt.

        Returns:
            {
                "score"             : float,       # 0.0 to 100.0
                "category"          : str,         # MALWARE | PHISHING | EXPLOIT | etc.
                "matched_terms"     : List[str],   # matched harm keywords
                "transformer_score" : float | None,# Secondary model score if available
                "is_fallback"       : bool,        # True if no transformer loaded
                "latency_ms"        : float
            }
        """
        t0 = time.perf_counter()

        kw = self._keyword_score(prompt)
        kw_score = kw["score"]
        category = kw["category"]
        matched_terms = kw["matched_terms"]

        transformer_score = self._transformer_score(prompt)

        # Fuse: if transformer is available, take max for safety (fail-secure)
        if transformer_score is not None:
            final_score = max(kw_score, transformer_score)
        else:
            final_score = kw_score

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "score": round(min(100.0, final_score), 2),
            "category": category,
            "matched_terms": matched_terms,
            "transformer_score": transformer_score,
            "is_fallback": transformer_score is None,
            "latency_ms": round(elapsed_ms, 3),
        }
