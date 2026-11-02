"""
Pydantic Schemas for Pillar II: Code Security & AST Vulnerability Detection
Strict typing for AST structures, secret findings, ML model scores, and gateway contracts.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

from core.malware.schemas import VerdictEnum, PolicyActionEnum


class ScanSourceEnum(str, Enum):
    AST = "AST"
    TAINT = "TAINT"
    SECRET = "SECRET"
    CODEBERT = "CODEBERT"
    REGEX = "REGEX"


class SecretMatch(BaseModel):
    kind: str
    line: int
    column: int = 0
    entropy: float
    verified_structure: bool
    redacted_preview: str
    variable_name: Optional[str] = None


class VulnerabilityFinding(BaseModel):
    cwe: str
    title: str
    line_start: int
    line_end: int
    confidence: float = Field(ge=0.0, le=1.0)
    tier: int = Field(ge=1, le=3)
    source: ScanSourceEnum
    evidence: str
    remediation: str
    suppressed_by: Optional[str] = None


class CodeBERTModelScore(BaseModel):
    status: str = "OK"  # "OK", "UNAVAILABLE", "ERROR"
    risk_score: float = 0.0
    confidence: float = 0.0
    latency_ms: float = 0.0
    is_trained: bool = True
    cwe_scores: Dict[str, float] = Field(default_factory=dict)
    model_version: str = "GraphCodeBERT-v2-DFG"


class ASTAnalysisReport(BaseModel):
    parser_backend: str  # "python_ast", "tree_sitter", "structural_fallback"
    language: str
    total_lines: int
    ast_nodes_count: int
    call_sites_count: int
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    taint_sinks_detected: int = 0
    suppression_comments_count: int = 0


class CodeScanRequest(BaseModel):
    code: str
    language: Optional[str] = "python"
    filename: Optional[str] = "snippet.py"
    options: Optional[Dict[str, Any]] = Field(default_factory=dict)


class CodeScanResult(BaseModel):
    scan_id: str
    sha256: str
    language: str
    filename: str
    total_lines: int
    verdict: VerdictEnum
    policy_action: PolicyActionEnum
    composite_risk_score: float
    confidence: float
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    secrets: List[SecretMatch] = Field(default_factory=list)
    ast_report: ASTAnalysisReport
    codebert_score: CodeBERTModelScore
    reasoning: str
    scan_latency_ms: float
    cached: bool = False
