"""
Developer 1 (Rohit Verma) — Master Judge Agent Consensus Engine
Coordinates Pattern Hunter, Semantic Analyst, and Behavioral Profiler.
Computes weighted composite risk, enforces high-severity overrides,
and synthesizes natural-language explainable reasoning.
"""

import re
import time
from typing import Dict, List, Any, Optional

from core.detection.pattern_hunter import PatternHunter
from core.detection.semantic_analyst import SemanticAnalyst
from core.detection.behavioral_profiler import BehavioralProfiler
from core.detection.stage2_arbiter import Stage2Arbiter
from core.detection.normalizer import normalize_text

class JudgeAgent:
    def __init__(
        self,
        threat_rules_path: str = "core/detection/threat_rules.json",
        stage2_arbiter: Optional[Stage2Arbiter] = None
    ):
        self.threat_rules_path = threat_rules_path
        self.pattern_hunter = PatternHunter(threat_rules_path=threat_rules_path)
        self.semantic_analyst = SemanticAnalyst()
        self.behavioral_profiler = BehavioralProfiler()
        self.stage2_arbiter = stage2_arbiter or Stage2Arbiter()

    def evaluate(self, prompt: str, session_id: str = "default") -> Dict[str, Any]:
        """
        Master multi-agent consensus evaluation engine.
        Coordinates Pattern Hunter, Semantic Analyst, and Behavioral Profiler.
        
        Returns:
            {
                "decision": "ALLOW" | "FLAG" | "BLOCK",
                "risk_score": float,        # 0.0 to 100.0
                "confidence": float,        # 0.0 to 1.0
                "agent_breakdown": {
                    "pattern_hunter_score": float,
                    "semantic_analyst_score": float,
                    "behavioral_profiler_score": float
                },
                "matched_signatures": List[str],
                "reasoning": str
            }
        """
        t0 = time.perf_counter()

        # Step 0: Ingress Normalization for Detection (Raw text preserved for LLM forwarding)
        inspected_prompt = normalize_text(prompt)

        # Step 1: Pattern Hunter (Fast Deterministic Heuristics & RegEx)
        pattern_res = self.pattern_hunter.scan(inspected_prompt)
        p_score = float(pattern_res.get("score", 0.0))
        matched = pattern_res.get("matched_signatures", [])

        # Step 2: Semantic Analyst (Deep NLP Transformer Sequence Classifier)
        semantic_res = self.semantic_analyst.analyze(inspected_prompt)
        s_score = float(semantic_res.get("score", 0.0))
        semantic_conf = float(semantic_res.get("confidence", 0.85))

        # Preliminary risk estimation for behavioral context
        preliminary_risk = max(p_score, s_score)

        # Step 3: Behavioral Profiler (Session & Temporal History)
        behavioral_res = self.behavioral_profiler.evaluate_session(
            session_id=session_id,
            prompt=inspected_prompt,
            preliminary_risk=preliminary_risk
        )
        b_score = float(behavioral_res.get("score", 0.0))
        escalation_detected = behavioral_res.get("escalation_detected", False)

        # Step 3.5: Stage 2 Online Deep Arbiter (Cascaded Heterogeneous Filter)
        # Tripwire check for explicit security keywords:
        TRIPWIRE_RE = re.compile(
            r"(?i)\b(jail\s*-?\s*break|bypass|override|disable\s+(safety|guardrails?|filters?)|"
            r"reveal\s+(system\s*prompt|source\s*code)|developer\s*mode|dan\s*mode)\b"
        )
        is_tripwire = bool(TRIPWIRE_RE.search(inspected_prompt) or TRIPWIRE_RE.search(prompt))

        # Short-prompt imperative uncertainty check (prompts <= 15 words containing extraction/security terms)
        words = inspected_prompt.split()
        is_short_suspicious = (len(words) <= 15) and any(
            w in inspected_prompt.lower() for w in ["jailbreak", "bypass", "sorce", "source", "system", "prompt", "override", "code"]
        )

        # Gating Criteria:
        # Invoke Stage 2 whenever semantic score is elevated (s_score >= 35.0), agent discrepancy exists,
        # or any sensitive keyword tripwire / short suspicious prompt is detected.
        is_already_decided = (p_score >= 95.0) or (s_score >= 85.0 and p_score >= 40.0)
        is_discrepancy_or_elevated = (
            (s_score >= 35.0) or (p_score >= 45.0) or (b_score >= 50.0) or is_tripwire or is_short_suspicious
        )

        stage2_data: Dict[str, Any] = {
            "invoked": False,
            "risk_score": None,
            "verdict": None,
            "is_attack": False,
            "reasoning": None,
            "is_fallback": False,
        }

        if (not is_already_decided) and is_discrepancy_or_elevated:
            stage2_data = self.stage2_arbiter.evaluate(prompt=prompt)

        # Step 4: Multi-Agent Weighted Composite Formula
        # Formula: (0.25 * Pattern) + (0.50 * Semantic) + (0.25 * Behavioral)
        composite_risk = (0.25 * p_score) + (0.50 * s_score) + (0.25 * b_score)

        # High-Confidence Corroborated Guardrails:
        # Tier 1: Deterministic High-Confidence Signature Match (DAN, Canary, System Override, Direct Jailbreak)
        if p_score >= 80.0:
            composite_risk = max(composite_risk, 85.0)

        # Tier 2: Corroborated Semantic Escalation (High Semantic + Structural Evidence)
        elif s_score >= 85.0 and p_score >= 40.0:
            composite_risk = max(composite_risk, 80.0)

        # Tier 3: Partial Mid-Tier Corroboration
        elif 70.0 <= s_score < 85.0 and p_score >= 40.0:
            composite_risk = max(composite_risk, 65.0)

        # Tier 4: Isolated Semantic Alert (e.g. shortcut on "ignore" without structural corroboration)
        # Clamped at FLAG (45 - 74): Never block alone, and never downgrade existing risk
        elif s_score >= 70.0:
            composite_risk = min(max(composite_risk, 45.0), 74.0)

        # Tier 5: Multi-Turn Behavioral Probing Escalation
        if escalation_detected and composite_risk < 50.0:
            composite_risk = max(composite_risk, 55.0)

        # Tier 6: Behavioral Suspicion Penalty (Flags session for review without blocking)
        elif b_score >= 50.0 and composite_risk < 40.0:
            composite_risk = max(composite_risk, 42.0)

        # Tier 7: Stage 2 Deep Arbiter Asymmetric Fusion
        if stage2_data.get("invoked"):
            s2_attack = stage2_data.get("is_attack", False)
            s2_risk = float(stage2_data.get("risk_score", 50.0))
            s2_verdict = stage2_data.get("verdict", "UNCERTAIN")
            s2_fallback = stage2_data.get("is_fallback", False)

            if s2_fallback:
                # Fallback on timeout or API failure:
                # If initial DeBERTa score was high, pattern matched, or tripwire fired, fail-closed to BLOCK
                if s_score >= 85.0 or p_score >= 80.0 or is_tripwire:
                    composite_risk = max(composite_risk, 80.0)
                else:
                    composite_risk = max(composite_risk, 45.0)
            elif s2_attack and (s2_risk >= 70.0 or s2_verdict == "ATTACK"):
                # Asymmetric Escalation: Stage 2 confirms attack -> BLOCK
                composite_risk = max(composite_risk, 80.0)
            elif (not s2_attack) and (s2_risk <= 30.0 or s2_verdict == "BENIGN"):
                # Disagreement check: If DeBERTa was extremely high (>= 95.0) but Stage 2 says BENIGN,
                # do NOT silently allow! Clamp to FLAG review floor (50.0).
                if s_score >= 95.0:
                    composite_risk = min(max(composite_risk, 45.0), 50.0)
                elif p_score < 30.0 and not escalation_detected and b_score < 30.0:
                    # Safe Attenuation: Both models/signals clear it
                    composite_risk = min(composite_risk, 30.0)
                else:
                    composite_risk = min(max(composite_risk, 42.0), 55.0)
            else:
                # Inconclusive or conflicting verdict: clamp to FLAG review floor
                composite_risk = max(composite_risk, 45.0)

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
        if s_score >= 85.0 and p_score >= 40.0:
            reasons.append(f"High semantic injection probability corroborated by signature ({s_score:.1f}/100)")
        elif s_score >= 70.0 and p_score < 40.0:
            reasons.append(f"Isolated semantic anomaly ({s_score:.1f}/100) without deterministic threat signature")
        elif s_score >= 60.0:
            reasons.append(f"Elevated semantic injection probability ({s_score:.1f}/100)")

        if stage2_data.get("invoked"):
            if stage2_data.get("is_fallback"):
                reasons.append("Stage 2 Deep Arbiter timeout/unreachable; safely defaulted to FLAG review")
            elif stage2_data.get("is_attack"):
                s2_reason = stage2_data.get("reasoning", "")
                reasons.append(f"Stage 2 Deep Arbiter (Gemini Flash) confirmed prompt injection ({stage2_data.get('risk_score', 0):.1f}/100): {s2_reason}")
            elif stage2_data.get("verdict") == "BENIGN":
                reasons.append(f"Stage 2 Deep Arbiter (Gemini Flash) validated prompt as benign ({stage2_data.get('risk_score', 0):.1f}/100)")

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
        if stage2_data.get("invoked") and not stage2_data.get("is_fallback"):
            overall_confidence = 0.96
        else:
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
                "behavioral_profiler_score": round(b_score, 2),
                "stage2_arbiter_score": round(stage2_data["risk_score"], 2) if stage2_data.get("invoked") and stage2_data.get("risk_score") is not None else None,
                "stage2_invoked": stage2_data.get("invoked", False)
            },
            "matched_signatures": matched,
            "reasoning": reasoning
        }
