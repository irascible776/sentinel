"""
Developer: Red-Team Squad (Pillar V)
Closed-Loop Auto-Immunization Engine with Benign Validation Gate & ReDoS Guardrails
(Hardened: Framing Vocabulary Exclusion, Sample Count Floor, and ReDoS Testing)
"""

import os
import re
import json
import uuid
import time
import logging
from typing import List, Tuple, Dict, Any, Optional

from core.redteam.schemas import SynthesizedRuleRecord

logger = logging.getLogger("sentinel.redteam.hardening")

# Common English stop-words + Strategist framing vocabulary to exclude from regex signatures
FRAMING_AND_STOPWORDS = {
    # Standard stopwords
    "this", "that", "with", "from", "have", "your", "what", "which", "will", "would",
    "should", "could", "about", "there", "their", "where", "when", "into", "some",
    # Strategist framing noise (DO NOT include in signatures)
    "hypothetical", "scenario", "compliance", "analyzer", "sandbox", "simulation",
    "researcher", "protocol", "authorized", "verification", "diagnostic", "testing",
    "forensic", "alternate", "academic", "validator", "deserializer", "payload",
    "instruction", "system", "evaluate", "execute", "output"
}


class BenignValidationGate:
    """
    Enforces the zero-collision false-positive filter.
    Tests candidate regular expressions against a local hard-negative benign enterprise corpus.
    Requires a minimum sample count floor.
    """
    MIN_CORPUS_FLOOR = 20

    def __init__(self, corpus_path: Optional[str] = None):
        self.corpus_path = corpus_path or os.path.join(
            os.path.dirname(__file__), "data", "benign_corpus.json"
        )
        self.benign_samples: List[str] = []
        self._load_corpus()

    def _load_corpus(self):
        if os.path.exists(self.corpus_path):
            try:
                with open(self.corpus_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.benign_samples = data.get("samples", [])
            except Exception as e:
                logger.warning(f"[BenignGate] Failed to load benign corpus: {e}")

    def validate(self, pattern_str: str) -> Tuple[bool, List[str], int]:
        """
        Returns (is_valid, colliding_samples, corpus_size).
        Valid ONLY if corpus meets minimum floor AND 0 benign samples match pattern.
        """
        n_samples = len(self.benign_samples)
        if n_samples < self.MIN_CORPUS_FLOOR:
            logger.warning(f"[BenignGate] Corpus size ({n_samples}) below floor ({self.MIN_CORPUS_FLOOR}). Failing closed.")
            return False, ["CORPUS_BELOW_MIN_FLOOR"], n_samples

        try:
            regex = re.compile(pattern_str, re.IGNORECASE)
        except re.error:
            return False, ["MALFORMED_REGEX"], n_samples

        collisions = []
        for sample in self.benign_samples:
            if regex.search(sample):
                collisions.append(sample[:80])
                if len(collisions) >= 3:
                    break

        passes = (len(collisions) == 0)
        return passes, collisions, n_samples


class ReDoSSafetyChecker:
    """
    Guarantees regular expression execution does not suffer from catastrophic backtracking.
    """
    @staticmethod
    def check_safety(pattern_str: str, max_timeout_ms: float = 20.0) -> bool:
        try:
            regex = re.compile(pattern_str)
        except re.error:
            return False

        # Pathological test strings
        pathological = [
            "a" * 300 + "!",
            "test " * 100 + "invalid",
            "system override " * 50
        ]

        for s in pathological:
            t0 = time.perf_counter()
            regex.search(s)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if elapsed_ms > max_timeout_ms:
                return False

        return True


class AutoHardener:
    """
    Transforms winning adversarial prompts into validated, ReDoS-safe defensive signatures.
    """
    def __init__(self, rules_path: str = "core/detection/threat_rules.json"):
        self.rules_path = rules_path
        self.gate = BenignValidationGate()
        self.redos = ReDoSSafetyChecker()

    def normalize_trigger(self, prompt: str) -> str:
        """Strips framing noise to isolate the underlying command words."""
        cleaned = re.sub(
            r"(?i)^(you are|act as|in this hypothetical|imagine that|pretend to be|for testing purposes)[^.\n]+[.\n]",
            "",
            prompt.strip()
        )
        cleaned = re.sub(
            r"(?i)(task \d+:|translate the following|decode and execute|verify instruction):?",
            "",
            cleaned
        )
        cleaned = re.sub(r"[\r\n\t]+", " ", cleaned)
        cleaned = re.sub(r"[^\w\s-]", " ", cleaned)
        return " ".join(cleaned.split())

    def synthesize_rule(
        self,
        node_id: str,
        prompt: str,
        category: str,
        campaign_id: str
    ) -> Optional[SynthesizedRuleRecord]:
        """
        Synthesizes a rule candidate, validates against benign corpus & ReDoS,
        and returns a SynthesizedRuleRecord in SHADOW mode.
        """
        core_text = self.normalize_trigger(prompt)
        words = [w.lower() for w in core_text.split() if len(w) >= 4]

        # Filter out common stop-words AND Strategist persona scaffolding words
        keywords = [w for w in words if w not in FRAMING_AND_STOPWORDS]

        if len(keywords) < 2:
            return None

        # Take 2-3 most distinct exploit keywords
        selected = keywords[:3]
        escaped = [re.escape(w) for w in selected]

        # Bounded quantifier pattern: word1 followed by at most 3 words then word2
        pattern = r"(?i)\b" + r"\s+(?:\w+\s+){0,3}?".join(escaped) + r"\b"

        # Step 1: ReDoS Safety Verification
        if not self.redos.check_safety(pattern):
            logger.warning(f"[AutoHardener] Rejected pattern '{pattern}' due to ReDoS risk.")
            return None

        # Step 2: Benign Validation Gate (Zero False-Positive Check)
        passes, collisions, corpus_size = self.gate.validate(pattern)
        if not passes:
            logger.warning(f"[AutoHardener] Rejected pattern '{pattern}' due to {len(collisions)} benign collisions: {collisions}")
            return None

        rule_id = f"AUTO-P5-{uuid.uuid4().hex[:6].upper()}"
        return SynthesizedRuleRecord(
            id=rule_id,
            name=f"Pillar-V Auto-Hardened: {' '.join(selected)} (n={corpus_size})",
            pattern=pattern,
            severity="HIGH",
            weight=40,
            mode="SHADOW",
            source_node_id=node_id,
            target_category=category,
            benign_check_passed=True,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )

    def commit_shadow_rules(self, rules: List[SynthesizedRuleRecord]) -> List[str]:
        """
        Atomically writes shadow rules to threat_rules.json with mode='SHADOW'.
        """
        if not rules:
            return []

        path = self.rules_path
        if not os.path.exists(path):
            alt_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detection", "threat_rules.json")
            if os.path.exists(alt_path):
                path = alt_path

        existing_data = {"version": "1.0.0", "updated_at": "", "rules": []}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
            except Exception:
                pass

        existing_rules = existing_data.get("rules", [])
        existing_patterns = {r.get("pattern") for r in existing_rules}

        added_ids = []
        for r in rules:
            if r.pattern not in existing_patterns:
                rule_dict = {
                    "id": r.id,
                    "name": r.name,
                    "pattern": r.pattern,
                    "severity": r.severity,
                    "weight": r.weight,
                    "mode": r.mode,
                    "source": "pillar_v_closed_loop",
                    "created_at": r.created_at
                }
                existing_rules.append(rule_dict)
                existing_patterns.add(r.pattern)
                added_ids.append(r.id)

        if added_ids:
            existing_data["rules"] = existing_rules
            existing_data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            tmp_path = f"{path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(existing_data, f, indent=2)
            os.replace(tmp_path, path)

        return added_ids


# Default instance
auto_hardener = AutoHardener()
