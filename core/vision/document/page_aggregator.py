"""
Document Page Risk Aggregator (Pillar III)
Aggregates page-by-page risk scores using asymmetric Max-Plus-Mean rollup
to prevent dilution of a single malicious page within a multi-page enterprise report.
"""

from typing import List, Tuple
from core.vision.schemas import (
    PageScanResult,
    DocHiddenTextFinding,
    VisionVerdictEnum,
    VisionPolicyActionEnum,
)
from core.vision.config import (
    MAX_PLUS_MEAN_PAGE_WEIGHT,
    RISK_THRESHOLD_ALLOW,
    RISK_THRESHOLD_BLOCK,
)


class PageAggregator:
    """
    Rolls up multi-page document findings into a document-level risk verdict.
    """

    def aggregate(
        self,
        pages: List[PageScanResult],
        findings: List[DocHiddenTextFinding],
    ) -> Tuple[float, VisionVerdictEnum, VisionPolicyActionEnum, str]:
        """
        Calculates max-plus-mean composite document risk.

        Returns:
            (composite_risk, verdict, policy_action, reasoning)
        """
        if not pages:
            return 0.0, VisionVerdictEnum.CLEAN, VisionPolicyActionEnum.ALLOW, "Document is empty."

        page_scores = [p.page_risk_score for p in pages]
        max_page_score = max(page_scores)
        mean_page_score = sum(page_scores) / len(page_scores)

        # Max-Plus-Mean formulation
        composite_risk = min(
            100.0, max_page_score + MAX_PLUS_MEAN_PAGE_WEIGHT * mean_page_score
        )

        has_critical = any(f.severity == "CRITICAL" for f in findings)
        if max_page_score >= RISK_THRESHOLD_BLOCK or has_critical:
            composite_risk = max(composite_risk, max_page_score, 85.0)
            verdict = VisionVerdictEnum.VISUAL_INJECTION
            policy_action = VisionPolicyActionEnum.BLOCK
            reasoning = (
                f"Document blocked: {len(findings)} structural hidden-text finding(s) detected "
                f"(peak page risk: {max_page_score:.1f})."
            )
            return round(composite_risk, 2), verdict, policy_action, reasoning

        # Determine verdict and policy action
        if composite_risk >= RISK_THRESHOLD_BLOCK:
            verdict = VisionVerdictEnum.VISUAL_INJECTION
            policy_action = VisionPolicyActionEnum.BLOCK
            reasoning = (
                f"Document blocked: {len(findings)} structural hidden-text finding(s) detected "
                f"(peak page risk: {max_page_score:.1f})."
            )
        elif composite_risk >= RISK_THRESHOLD_ALLOW:
            verdict = VisionVerdictEnum.SUSPICIOUS
            policy_action = VisionPolicyActionEnum.FLAG
            reasoning = (
                f"Document flagged for manual review: moderate anomalies detected "
                f"across {len(pages)} pages (composite risk: {composite_risk:.1f})."
            )
        else:
            verdict = VisionVerdictEnum.CLEAN
            policy_action = VisionPolicyActionEnum.ALLOW
            reasoning = f"Document verified clean across all {len(pages)} pages."

        return round(composite_risk, 2), verdict, policy_action, reasoning


# Global page aggregator instance
page_aggregator = PageAggregator()
