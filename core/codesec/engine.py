"""
Unified Code Security & AST Vulnerability Engine (Pillar II)
Orchestrates AST Taint Analysis, Secret Scanner, GraphCodeBERT Classifier, and 3-Tier Judge.
Includes thread-safe SHA-256 LRU caching, size limits, and robust failure isolation.
"""

import time
import uuid
import hashlib
import threading
from collections import OrderedDict
from typing import Optional, Dict, Any, List

from core.codesec.config import (
    MAX_CODE_SIZE_BYTES,
    MAX_CODE_LINES,
    MAX_CACHE_SIZE,
)
from core.codesec.schemas import (
    CodeScanRequest,
    CodeScanResult,
    VerdictEnum,
    PolicyActionEnum,
    VulnerabilityFinding,
)
from core.codesec.secret_scanner import SecretScanner
from core.codesec.ast_parser import ASTParserEngine
from core.codesec.codebert_head import codebert_classifier
from core.codesec.judge import code_judge


class CodeSecurityEngine:
    """
    Enterprise-grade Code Security Analysis Engine.
    Coordinates deterministic static AST visitors, regex/entropy credential scanning,
    deep neural GraphCodeBERT embeddings, and 3-tier consensus arbitration.
    """

    def __init__(self):
        self.secret_scanner = SecretScanner()
        self.ast_parser = ASTParserEngine()
        self.classifier = codebert_classifier
        self.judge = code_judge

        # Thread-safe LRU cache: sha256 -> CodeScanResult
        self._cache: OrderedDict[str, CodeScanResult] = OrderedDict()
        self._lock = threading.Lock()

    def _get_cache_key(self, code: str, language: str) -> str:
        payload = f"{language.lower()}:{code}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def scan_code(
        self,
        code: str,
        language: str = "python",
        filename: str = "snippet.py",
        options: Optional[Dict[str, Any]] = None,
    ) -> CodeScanResult:
        start_time = time.perf_counter()
        scan_id = str(uuid.uuid4())
        code_sha256 = hashlib.sha256(code.encode("utf-8")).hexdigest()

        # 1. Payload Size & Limit Validations
        code_bytes = code.encode("utf-8")
        lines = code.splitlines()
        if len(code_bytes) > MAX_CODE_SIZE_BYTES or len(lines) > MAX_CODE_LINES:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            limit_msg = (
                f"Payload size ({len(code_bytes)} bytes) exceeds limit of {MAX_CODE_SIZE_BYTES} bytes."
                if len(code_bytes) > MAX_CODE_SIZE_BYTES
                else f"Payload line count ({len(lines)}) exceeds maximum limit of {MAX_CODE_LINES} lines."
            )
            finding = VulnerabilityFinding(
                cwe="CWE-400",
                title="Uncontrolled Resource Consumption (Oversized Code)",
                line_start=1,
                line_end=1,
                confidence=1.0,
                tier=1,
                source="AST",
                evidence=limit_msg,
                remediation="Split large codebases into modular functional units or files before submission.",
            )
            return CodeScanResult(
                scan_id=scan_id,
                sha256=code_sha256,
                language=language,
                filename=filename,
                total_lines=len(lines),
                verdict=VerdictEnum.UNSCANNABLE,
                policy_action=PolicyActionEnum.REJECT,
                composite_risk_score=100.0,
                confidence=1.0,
                findings=[finding],
                secrets=[],
                ast_report=self.ast_parser.analyze_code("", language=language),
                codebert_score=self.classifier.score_code(""),
                reasoning=limit_msg,
                scan_latency_ms=elapsed_ms,
                cached=False,
            )

        # 2. Check LRU Cache
        cache_key = self._get_cache_key(code, language)
        with self._lock:
            if cache_key in self._cache:
                self._cache.move_to_end(cache_key)
                cached_res = self._cache[cache_key].model_copy(deep=True)
                cached_res.cached = True
                cached_res.scan_latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                return cached_res

        try:
            # 3. Step 1: Secret Scanning (High-Entropy & Regex Patterns)
            secrets, secret_findings = self.secret_scanner.scan_code(code)

            # 4. Step 2: AST Parsing & Taint Analysis
            ast_report = self.ast_parser.analyze_code(code, language=language)

            # 5. Step 3: GraphCodeBERT Sequence Embedding Scoring
            codebert_score = self.classifier.score_code(code)

            # Aggregate all findings
            all_findings = list(secret_findings) + list(ast_report.findings)

            # 6. Step 4: 3-Tier Precedence Consensus Judgment
            verdict, policy_action, composite_risk, confidence, reasoning = self.judge.evaluate(
                ast_report=ast_report,
                codebert_score=codebert_score,
                secrets=secrets,
                all_findings=all_findings,
            )
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            finding = VulnerabilityFinding(
                cwe="CWE-398",
                title="Analysis Processing Exception",
                line_start=1,
                line_end=1,
                confidence=0.90,
                tier=2,
                source="ENGINE",
                evidence=f"Internal engine parser error: {str(e)[:80]}",
                remediation="Check syntax validity and language compatibility.",
            )
            return CodeScanResult(
                scan_id=scan_id,
                sha256=code_sha256,
                language=language,
                filename=filename,
                total_lines=len(lines),
                verdict=VerdictEnum.UNSCANNABLE,
                policy_action=PolicyActionEnum.QUARANTINE,
                composite_risk_score=50.0,
                confidence=0.80,
                findings=[finding],
                secrets=[],
                ast_report=self.ast_parser.analyze_code("", language=language),
                codebert_score=self.classifier.score_code(""),
                reasoning="Internal exception during code analysis pipeline; payload quarantined safely.",
                scan_latency_ms=elapsed_ms,
                cached=False,
            )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        result = CodeScanResult(
            scan_id=scan_id,
            sha256=code_sha256,
            language=language,
            filename=filename,
            total_lines=ast_report.total_lines,
            verdict=verdict,
            policy_action=policy_action,
            composite_risk_score=composite_risk,
            confidence=confidence,
            findings=all_findings,
            secrets=secrets,
            ast_report=ast_report,
            codebert_score=codebert_score,
            reasoning=reasoning,
            scan_latency_ms=elapsed_ms,
            cached=False,
        )

        # Store in LRU Cache (do not cache corrupted or error states)
        if verdict != VerdictEnum.UNSCANNABLE:
            with self._lock:
                if len(self._cache) >= MAX_CACHE_SIZE:
                    self._cache.popitem(last=False)
                self._cache[cache_key] = result.model_copy(deep=True)

        return result


# Global singleton instance
code_security_engine = CodeSecurityEngine()
