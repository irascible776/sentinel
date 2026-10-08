"""
Developer 1 (Rohit Verma) — Master Judge Agent Consensus Engine
Coordinates Pattern Hunter, Semantic Analyst, and Behavioral Profiler.
Computes weighted composite risk, enforces high-severity overrides,
and synthesizes natural-language explainable reasoning.
"""

import time
from typing import Dict, List, Any, Optional

from core.detection.pattern_hunter import PatternHunter
from core.detection.semantic_analyst import SemanticAnalyst
from core.detection.behavioral_profiler import BehavioralProfiler

class JudgeAgent:
    def __init__(self, threat_rules_path: str = "core/detection/threat_rules.json"):
        self.threat_rules_path = threat_rules_path
        self.pattern_hunter = PatternHunter(threat_rules_path=threat_rules_path)
        self.semantic_analyst = SemanticAnalyst()
        self.behavioral_profiler = BehavioralProfiler()

    def evaluate(self, prompt: str, session_id: str = "default") -> Dict[str, Any]:
        """
        Master synchronous/in-process multi-agent evaluation interface.
        Directly imported by Developer 2's Gateway (app.py) and Developer 3's RAG Scanner.
        
        Returns:
            {
                "decision": "ALLOW" | "FLAG" | "BLOCK",
                "risk_score": float,        # 0.0 to 100.0
                "confidence": float,        # 0.0 to 1.0
                "agent_breakdown": {
                    "pattern_hunter_score": float,     # 0.0 to 100.0
                    "semantic_analyst_score": float,   # 0.0 to 100.0
                    "behavioral_profiler_score": float # 0.0 to 100.0
                },
                "matched_signatures": List[str],       # e.g. ["DAN Persona", "Direct Override"]
                "reasoning": str                       # Human-readable explanation
            }
        """
        t0 = time.perf_counter()

        # Step 1: Pattern Hunter (Fast Heuristics & RegEx)
        pattern_res = self.pattern_hunter.scan(prompt)
        p_score = float(pattern_res.get("score", 0.0))
        matched = pattern_res.get("matched_signatures", [])

        # Step 2: Semantic Analyst (Deep NLP Transformer)
        semantic_res = self.semantic_analyst.analyze(prompt)
        s_score = float(semantic_res.get("score", 0.0))
        semantic_conf = float(semantic_res.get("confidence", 0.85))

        # Preliminary risk estimation for behavioral context
        preliminary_risk = max(p_score, s_score)

        # Step 3: Behavioral Profiler (Session & Temporal History)
        behavioral_res = self.behavioral_profiler.evaluate_session(
            session_id=session_id,
            prompt=prompt,
            preliminary_risk=preliminary_risk
        )
        b_score = float(behavioral_res.get("score", 0.0))
        escalation_detected = behavioral_res.get("escalation_detected", False)

        # Step 4: Multi-Agent Weighted Composite Formula
        # Formula: (0.25 * Pattern) + (0.50 * Semantic) + (0.25 * Behavioral)
        composite_risk = (0.25 * p_score) + (0.50 * s_score) + (0.25 * b_score)

        # High-Confidence Override Guardrails:
        # 1. Critical Pattern Override: Blatant high-weight regex match triggers immediate rejection
        if p_score >= 90.0:
            composite_risk = max(composite_risk, 85.0)

        # 2. Deep Semantic Override: Strong transformer certainty on adversarial intent
        if s_score >= 85.0 and semantic_conf >= 0.90:
            composite_risk = max(composite_risk, 80.0)

        # 3. Behavioral Probing Escalation Override
        if escalation_detected and composite_risk < 50.0:
            composite_risk = max(composite_risk, 55.0)

        # 4. Behavioral Suspicion / Prior Attack Penalty
        if b_score >= 50.0 and composite_risk < 40.0:
            composite_risk = max(composite_risk, 42.0)

        composite_risk = round(max(0.0, min(100.0, composite_risk)), 2)

        # Step 5: Three-Tier Decision Classification
        if composite_risk >= 75.0:
            decision = "BLOCK"
        elif composite_risk >= 40.0:
            decision = "FLAG"
        else:
            decision = "ALLOW"

        # Step 6: Natural-Language Explainable Reasoning Synthesis
        reasons: List[str] = []
        if matched:
            reasons.append(f"Matched adversarial signature(s): {', '.join(matched)}")
        if s_score >= 60.0:
            reasons.append(f"High semantic injection probability ({s_score:.1f}/100)")
        if escalation_detected:
            reasons.append("Multi-turn probing escalation detected across recent interactions")
        elif b_score > 30.0:
            reasons.append("Elevated request velocity or prior suspicious activity in session")

        if decision == "BLOCK":
            details = "; ".join(reasons) if reasons else "Adversarial prompt injection pattern identified"
            reasoning = f"Request blocked by AI Security Gateway (Risk: {composite_risk:.1f}/100). {details}."
        elif decision == "FLAG":
            details = "; ".join(reasons) if reasons else "Borderline or ambiguous request characteristics"
            reasoning = f"Request flagged for security review (Risk: {composite_risk:.1f}/100). {details}."
        else:
            reasoning = "Prompt verified clean and safe by AI Security Gateway multi-agent consensus."

        # Overall consensus confidence score
        overall_confidence = round(
            0.95 if matched or semantic_conf >= 0.90 else (0.85 if decision == "ALLOW" else 0.88),
            4
        )

        return {
            "decision": decision,
            "risk_score": composite_risk,
            "confidence": overall_confidence,
            "agent_breakdown": {
                "pattern_hunter_score": round(p_score, 2),
                "semantic_analyst_score": round(s_score, 2),
                "behavioral_profiler_score": round(b_score, 2)
            },
            "matched_signatures": matched,
            "reasoning": reasoning
        }
