"""
Master Code Security Judge Consensus Engine (Pillar II)
Enforces 3-Tier Precedence Consensus across AST Taint Analysis, GraphCodeBERT, and Secret Scanning.
"""

from typing import List, Tuple, Dict, Any

from core.codesec.config import (
    RISK_THRESHOLD_MALICIOUS,
    RISK_THRESHOLD_SUSPICIOUS,
    RISK_THRESHOLD_SAFE,
    WEIGHT_AST_ANALYSIS,
    WEIGHT_CODEBERT_MODEL,
    WEIGHT_SECRET_SCANNER,
)
from core.codesec.schemas import (
    ASTAnalysisReport,
    SecretMatch,
    VulnerabilityFinding,
    CodeBERTModelScore,
    VerdictEnum,
    PolicyActionEnum,
)


class CodeSecurityJudge:
    """
    Evaluates multi-source code security signals into an enterprise policy verdict.
    Enforces 3-Tier Precedence:
      Tier 1: High-Confidence Known-Bad Overrides (Direct SQLi, RCE, Pickle, Verified Keys) -> BLOCK
      Tier 2: High-Confidence Known-Good Overrides (Sanitized, Parameterized, Valid # nosec) -> ALLOW
      Tier 3: Calibrated Ensemble (AST 35% + CodeBERT 45% + Secrets 20%)
    """

    def evaluate(
        self,
        ast_report: ASTAnalysisReport,
        codebert_score: CodeBERTModelScore,
        secrets: List[SecretMatch],
        all_findings: List[VulnerabilityFinding],
    ) -> Tuple[VerdictEnum, PolicyActionEnum, float, float, str]:
        """
        Returns:
            (verdict, policy_action, composite_risk, confidence, reasoning)
        """
        # Case 0: Empty code
        if ast_report.total_lines == 0 and not all_findings:
            return (
                VerdictEnum.CLEAN,
                PolicyActionEnum.ALLOW,
                0.0,
                1.0,
                "Empty code payload verified clean.",
            )

        # Separate unsuppressed findings from suppressed findings
        unsuppressed_findings = [f for f in all_findings if not f.suppressed_by]
        unsuppressed_tier1 = [f for f in unsuppressed_findings if f.tier == 1]
        suppressed_findings = [f for f in all_findings if f.suppressed_by]
        has_verified_secret = any(s.verified_structure for s in secrets)

        # --- TIER 1: High-Confidence Known-Bad Overrides ---
        if unsuppressed_tier1 or has_verified_secret:
            cwes = sorted(list({f.cwe for f in unsuppressed_tier1} | ({"CWE-798"} if has_verified_secret else set())))
            evidence_items = [f"{f.cwe} ({f.evidence[:80]})" for f in unsuppressed_tier1[:2]]
            if has_verified_secret and not evidence_items:
                evidence_items.append("CWE-798 (Verified cryptographic or cloud provider credentials detected)")
            evidence_summary = "; ".join(evidence_items)
            reason = f"High-confidence vulnerability detected [{', '.join(cwes)}]: {evidence_summary}"
            max_conf = max([f.confidence for f in unsuppressed_tier1] + ([0.99] if has_verified_secret else [0.90]))
            risk_score = min(99.0, 95.0 + max(0.0, (len(unsuppressed_tier1) - 1) * 2.0))

            return (
                VerdictEnum.MALICIOUS,
                PolicyActionEnum.BLOCK,
                risk_score,
                max_conf,
                reason,
            )

        # --- TIER 2: High-Confidence Known-Good Overrides ---
        # Tier 2 bypass requires that ALL findings are suppressed, zero secrets exist, and model risk is low.
        if suppressed_findings and not unsuppressed_findings:
            # Critical check: Tier-1 vulnerabilities (RCE, SQLi, Deserialization) CANNOT be bypassed to ALLOW purely via inline comments
            had_tier1_suppressed = any(getattr(f, "tier", 2) == 1 for f in suppressed_findings)
            if had_tier1_suppressed or secrets or codebert_score.risk_score >= RISK_THRESHOLD_SUSPICIOUS:
                # Route suppressed critical findings or suspicious model signals to QUARANTINE instead of blind ALLOW
                reason = "Suppressed critical security finding or elevated neural risk requires manual security authorization."
                return (
                    VerdictEnum.SUSPICIOUS,
                    PolicyActionEnum.QUARANTINE,
                    round(max(codebert_score.risk_score, 50.0), 2),
                    0.85,
                    reason,
                )

            suppress_reasons = sorted(list({f.suppressed_by for f in suppressed_findings if f.suppressed_by}))
            suppressed_risk = round(min(codebert_score.risk_score * 0.2, 18.0), 2)
            reason = f"All findings verified with security annotations ({', '.join(suppress_reasons)}). Risk suppressed below threshold."
            return (
                VerdictEnum.CLEAN,
                PolicyActionEnum.ALLOW,
                suppressed_risk,
                0.90,
                reason,
            )

        # If zero findings, zero secrets, and low model risk
        if not all_findings and not secrets and codebert_score.risk_score < RISK_THRESHOLD_SAFE:
            return (
                VerdictEnum.CLEAN,
                PolicyActionEnum.ALLOW,
                round(codebert_score.risk_score, 2),
                0.95,
                "Zero AST taint sinks, no hard-coded secrets, and neural model confirms clean code.",
            )

        # --- TIER 3: Calibrated Ensemble (Evaluates Remaining Unsuppressed Findings) ---
        # Calculate AST Risk component using unsuppressed findings with tier weighting
        ast_risk = 0.0
        if unsuppressed_findings:
            ast_risk = min(100.0, sum((80.0 if f.tier == 1 else 40.0) * f.confidence for f in unsuppressed_findings))

        # Calculate Secret Risk component (avoid double-counting with verified secrets which trigger Tier 1)
        secret_risk = 0.0
        if secrets:
            secret_risk = min(100.0, sum(s.entropy * 12.0 for s in secrets))

        # Model Risk component
        model_risk = codebert_score.risk_score

        # Weighted combination
        composite_risk = (
            (WEIGHT_AST_ANALYSIS * ast_risk)
            + (WEIGHT_CODEBERT_MODEL * model_risk)
            + (WEIGHT_SECRET_SCANNER * secret_risk)
        )

        # Single-signal dominance ceilings to prevent dilution of high-risk signals
        if model_risk >= 85.0:
            composite_risk = max(composite_risk, model_risk)
        if secret_risk >= 75.0:
            composite_risk = max(composite_risk, secret_risk)
        if ast_risk >= 85.0:
            composite_risk = max(composite_risk, ast_risk)

        composite_risk = round(min(100.0, max(0.0, composite_risk)), 2)

        # Compute ensemble confidence based on signal agreement
        signals_active = sum([ast_risk > 20.0, model_risk > 20.0, secret_risk > 20.0])
        confidence = 0.85 if signals_active >= 2 else 0.70

        # Verdict Decision
        if composite_risk >= RISK_THRESHOLD_MALICIOUS:
            verdict = VerdictEnum.MALICIOUS
            policy_action = PolicyActionEnum.BLOCK
            reason = f"Composite risk ({composite_risk:.1f}/100) exceeds blocking threshold. Multi-agent consensus flagged vulnerabilities."
        elif composite_risk >= RISK_THRESHOLD_SUSPICIOUS:
            verdict = VerdictEnum.SUSPICIOUS
            policy_action = PolicyActionEnum.QUARANTINE
            reason = f"Composite risk ({composite_risk:.1f}/100) in suspicious quarantine range. Manual review or sandbox analysis recommended."
        else:
            verdict = VerdictEnum.CLEAN
            policy_action = PolicyActionEnum.ALLOW
            reason = f"Composite risk ({composite_risk:.1f}/100) within permissible safety boundaries."

        return (
            verdict,
            policy_action,
            composite_risk,
            confidence,
            reason,
        )


# Global singleton instance
code_judge = CodeSecurityJudge()
