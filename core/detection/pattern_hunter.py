"""
Developer 1 (Rohit Verma) — Pattern Hunter Agent
Ingress heuristic, signature, regex and de-obfuscation scanner.
Hot-reloads threat_rules.json dynamically when modified by Utkarsh's Threat Intelligence Feed.
"""

import os
import re
import json
import time
import base64
from typing import Dict, List, Any, Optional, Tuple

class PatternHunter:
    def __init__(self, threat_rules_path: str = "core/detection/threat_rules.json"):
        self.threat_rules_path = threat_rules_path
        self._rules: List[Dict[str, Any]] = []
        self._compiled_rules: List[Tuple[Dict[str, Any], re.Pattern]] = []
        self._last_mtime: float = 0.0
        self.load_rules()

    def load_rules(self) -> bool:
        """
        Loads and compiles threat rules from JSON.
        Hot-reloads locklessly whenever the file's modification time (mtime) changes.
        """
        if not os.path.exists(self.threat_rules_path):
            return False

        try:
            mtime = os.path.getmtime(self.threat_rules_path)
            if mtime > self._last_mtime:
                with open(self.threat_rules_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                raw_rules = data.get("rules", [])
                compiled: List[Tuple[Dict[str, Any], re.Pattern]] = []

                for rule in raw_rules:
                    pattern_str = rule.get("pattern", "")
                    if not pattern_str:
                        continue
                    try:
                        regex = re.compile(pattern_str)
                        compiled.append((rule, regex))
                    except re.error:
                        # Skip malformed regex without crashing
                        continue

                self._rules = raw_rules
                self._compiled_rules = compiled
                self._last_mtime = mtime
                return True
        except (json.JSONDecodeError, OSError):
            # If file is mid-write by Developer 3's ThreatFeed, preserve current rules
            pass
        return False

    def extract_and_decode_base64(self, text: str) -> List[str]:
        """
        Scans for Base64 encoded payload blocks and decodes them to UTF-8 plaintext.
        Allows inspecting obfuscated attack payloads.
        """
        decoded_payloads: List[str] = []
        # Match base64-like substrings of at least 16 characters ending in optional padding:
        potential_b64 = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)

        for token in potential_b64:
            try:
                # Add padding if missing:
                missing_padding = len(token) % 4
                if missing_padding:
                    token_padded = token + "=" * (4 - missing_padding)
                else:
                    token_padded = token

                raw_bytes = base64.b64decode(token_padded, validate=True)
                decoded_str = raw_bytes.decode("utf-8", errors="ignore").strip()

                # Keep if decoded text contains printable characters with words
                if len(decoded_str) >= 4 and any(c.isalpha() for c in decoded_str):
                    decoded_payloads.append(decoded_str)
            except Exception:
                continue

        return decoded_payloads

    def scan(self, prompt: str) -> Dict[str, Any]:
        """
        Scans original prompt and decoded strings against compiled regex rules.
        
        Returns:
            {
                "score": float,                  # 0.0 to 100.0 (highest matched weight)
                "matched_signatures": List[str], # Rule names (e.g. ["Direct Override", "DAN Persona"])
                "matched_ids": List[str],        # Rule IDs (e.g. ["SIG-001", "SIG-002"])
                "obfuscation_detected": bool,
                "decoded_payloads": List[str],
                "latency_ms": float
            }
        """
        t0 = time.perf_counter()
        self.load_rules()

        matched_signatures: List[str] = []
        matched_ids: List[str] = []
        pattern_score = 0.0

        # Include original, normalized, and decoded Base64 text targets
        from core.detection.normalizer import normalize_text
        normalized_prompt = normalize_text(prompt)

        decoded_payloads = self.extract_and_decode_base64(prompt)
        text_targets = [prompt]
        if normalized_prompt and normalized_prompt != prompt:
            text_targets.append(normalized_prompt)
        text_targets.extend(decoded_payloads)

        for text in text_targets:
            for rule, regex in self._compiled_rules:
                if regex.search(text):
                    rule_name = rule.get("name", "Unknown Signature")
                    rule_id = rule.get("id", "SIG-UNK")
                    weight = float(rule.get("weight", 80.0))

                    if rule_name not in matched_signatures:
                        matched_signatures.append(rule_name)
                    if rule_id not in matched_ids:
                        matched_ids.append(rule_id)

                    pattern_score = max(pattern_score, weight)

        # Base64 obfuscation alone adds minimum suspicion if payload was successfully decoded:
        obfuscation_detected = len(decoded_payloads) > 0
        if obfuscation_detected and pattern_score < 40.0:
            pattern_score = max(pattern_score, 45.0)
            if "Base64 Obfuscation Detected" not in matched_signatures:
                matched_signatures.append("Base64 Obfuscation Detected")

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "score": round(min(100.0, pattern_score), 2),
            "matched_signatures": matched_signatures,
            "matched_ids": matched_ids,
            "obfuscation_detected": obfuscation_detected,
            "decoded_payloads": decoded_payloads,
            "latency_ms": round(elapsed_ms, 3)
        }
