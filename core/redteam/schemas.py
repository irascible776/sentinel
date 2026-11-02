"""
Developer: Red-Team Squad (Pillar V)
Pydantic Schemas for Adversarial Robustness & Security Auditing Engine
(Refined with Claude Security Review Findings)
"""

from enum import Enum
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, SecretStr


class TargetType(str, Enum):
    SENTINEL_LOCAL = "sentinel_local"
    OLLAMA = "ollama"
    VLLM_OPENAI = "vllm_openai"
    GENERIC_HTTP = "generic_http"


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    CANARY_EXFILTRATION = "canary_exfiltration"
    TOOL_HIJACKING = "tool_hijacking"
    DATA_LEAKAGE = "data_leakage"


class AuditVerdict(str, Enum):
    PENDING = "PENDING"
    REFUSED = "REFUSED"                     # Tier 1: Target safely declined
    EVASIVE_NEUTRAL = "EVASIVE_NEUTRAL"     # Tier 2: Target deflected / generic boilerplate
    COMPLIED_BENIGN = "COMPLIED_BENIGN"     # Tier 3: Target executed wrapped task harmlessly
    VIOLATION_CONFIRMED = "VIOLATION_CONFIRMED"  # Tier 4: Objective breach verified
    ERROR = "ERROR"                         # Transport / target failure (excluded from metrics)


class TargetResponse(BaseModel):
    raw_response: str = ""
    latency_ms: float = 0.0
    status_code: int = 200
    decision: Optional[str] = None          # 'ALLOW', 'BLOCK', 'FLAG' if provided by gateway
    oracle_score: Optional[float] = None    # None if failed or target has no oracle
    valid: bool = True                      # False if HTTP error, timeout, or malformed JSON
    headers: Dict[str, str] = Field(default_factory=dict)
    error: Optional[str] = None


class StartAuditRequest(BaseModel):
    target_type: TargetType = Field(default=TargetType.SENTINEL_LOCAL)
    target_endpoint: str = Field(default="http://127.0.0.1:8000")
    target_model: Optional[str] = Field(default=None)
    api_key: Optional[SecretStr] = Field(default=None)
    categories: List[AttackCategory] = Field(
        default=[
            AttackCategory.PROMPT_INJECTION,
            AttackCategory.CANARY_EXFILTRATION,
            AttackCategory.TOOL_HIJACKING,
            AttackCategory.DATA_LEAKAGE
        ],
        min_length=1
    )
    max_turns: int = Field(default=4, ge=1, le=6, description="Maximum search depth D")
    beam_width: int = Field(default=3, ge=1, le=4, description="Beam width W")
    branch_factor: int = Field(default=2, ge=1, le=3, description="Mutations per node B")
    auto_harden_shadow: bool = Field(default=True, description="Stage newly synthesized rules in shadow mode")


class AuditNodeRecord(BaseModel):
    node_id: str
    campaign_id: str
    seed_id: str = "SEED-000"
    category: str = "prompt_injection"
    parent_id: Optional[str] = None
    depth: int = 0
    mutation_type: str = "ROOT_SEED"
    prompt_text: str
    response_text: str = ""
    target_score: Optional[float] = None
    intent_similarity: float = 1.0
    verdict: AuditVerdict = AuditVerdict.PENDING
    oracle_hit: str = "NONE"
    created_at: str


class AuditCampaignRecord(BaseModel):
    campaign_id: str
    target_type: str
    target_endpoint: str
    target_model: Optional[str] = None
    status: str = "QUEUED"  # QUEUED, RUNNING, COMPLETED, FAILED, PAUSED
    total_seeds: int = 0
    total_nodes_evaluated: int = 0
    breaches_detected: int = 0
    rules_synthesized: int = 0
    created_at: str
    completed_at: Optional[str] = None


class SynthesizedRuleRecord(BaseModel):
    id: str
    name: str
    pattern: str
    severity: str = "HIGH"
    weight: int = 40
    mode: str = "SHADOW"
    source_node_id: str
    target_category: str
    benign_check_passed: bool = True
    created_at: str


class AuditReportResponse(BaseModel):
    campaign: AuditCampaignRecord
    nodes: List[AuditNodeRecord] = Field(default_factory=list)
    summary_by_category: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    rules_generated: List[SynthesizedRuleRecord] = Field(default_factory=list)
    resilience_score: Optional[float] = None  # Percentage of seeds that remained unbreached
