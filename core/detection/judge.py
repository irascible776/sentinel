"""
Developer 1 (Rohit) - Master Judge Agent Interface Skeleton
Provides heuristic baseline detection so Developer 2 (Rupesh) can start the Gateway immediately.
Rohit replaces/enhances internal methods with DeBERTa transformer and session profiler.
"""

import os
import re
import json
from typing import Dict, List, Any

class JudgeAgent:
    def __init__(self, threat_rules_path: str = "core/detection/threat_rules.json"):
        self.threat_rules_path = threat_rules_path
        self._rules = []
        self._rules_mtime = 0
        self.load_rules()

    def load_rules(self):
        """Loads and auto-reloads threat_rules.json when updated by Utkarsh's Threat Feed."""
        if os.path.exists(self.threat_rules_path):
            try:
                mtime = os.path.getmtime(self.threat_rules_path)
                if mtime > self._rules_mtime:
                    with open(self.threat_rules_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self._rules = data.get("rules", [])
                        self._rules_mtime = mtime
            except Exception:
                pass

    def evaluate(self, prompt: str, session_id: str = "default") -> Dict[str, Any]:
        """
        Master evaluation interface called by Rupesh's Gateway and Utkarsh's RAG scanner.
        """
        self.load_rules()
        matched = []
        pattern_score = 0.0

        # Pattern Hunter heuristic check:
        for rule in self._rules:
            pattern = rule.get("pattern", "")
            if pattern and re.search(pattern, prompt, re.IGNORECASE):
                matched.append(rule.get("name", "Unknown Signature"))
                pattern_score = max(pattern_score, float(rule.get("weight", 80)))

        # Baseline Semantic & Behavioral scores (enhanced by Rohit's sub-modules):
        semantic_score = pattern_score * 0.9 if pattern_score > 0 else 5.0
        behavioral_score = 10.0

        # Composite Risk Formula: (0.25 * Pattern) + (0.50 * Semantic) + (0.25 * Behavioral)
        overall_risk = (0.25 * pattern_score) + (0.50 * semantic_score) + (0.25 * behavioral_score)

        if overall_risk >= 75.0:
            decision = "BLOCK"
            reasoning = f"Attack blocked due to high composite risk ({overall_risk:.1f}/100). Matched: {', '.join(matched) if matched else 'Adversarial intent'}."
        elif overall_risk >= 40.0:
            decision = "FLAG"
            reasoning = f"Suspicious activity flagged ({overall_risk:.1f}/100)."
        else:
            decision = "ALLOW"
            reasoning = "Prompt verified clean by AI Security Gateway."

        return {
            "decision": decision,
            "risk_score": round(overall_risk, 2),
            "confidence": 0.95 if matched else 0.85,
            "agent_breakdown": {
                "pattern_hunter_score": round(pattern_score, 2),
                "semantic_analyst_score": round(semantic_score, 2),
                "behavioral_profiler_score": round(behavioral_score, 2)
            },
            "matched_signatures": matched,
            "reasoning": reasoning
        }
