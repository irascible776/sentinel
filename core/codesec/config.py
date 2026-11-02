"""
Pillar II: Code Security & AST Vulnerability Detection Configuration
Defines CWE metadata, confidence thresholds, ensemble weights, and regex patterns.
"""

from typing import Dict, List, Any

# Target CWE Definitions
TARGET_CWES: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "description": "Improper neutralization of special elements used in an SQL command",
        "severity": "CRITICAL",
        "default_risk": 92.0,
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "description": "Improper neutralization of special elements used in an OS command",
        "severity": "CRITICAL",
        "default_risk": 95.0,
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "Deserialization of untrusted input without verification (pickle, yaml, eval)",
        "severity": "HIGH",
        "default_risk": 88.0,
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "description": "Hard-coded cryptographic keys, AWS credentials, JWTs, or private keys",
        "severity": "HIGH",
        "default_risk": 85.0,
    },
}

# Supported Languages
SUPPORTED_LANGUAGES: List[str] = ["python", "javascript", "java", "c", "cpp", "go", "php"]

# Decision Thresholds
RISK_THRESHOLD_MALICIOUS: float = 75.0   # >= 75: BLOCK
RISK_THRESHOLD_SUSPICIOUS: float = 40.0  # 40 - 74: QUARANTINE / ALERT
RISK_THRESHOLD_SAFE: float = 20.0        # < 20: ALLOW

# Tier 3 Calibrated Ensemble Weights (when no Tier 1 or Tier 2 override triggers)
WEIGHT_AST_ANALYSIS: float = 0.35
WEIGHT_CODEBERT_MODEL: float = 0.45
WEIGHT_SECRET_SCANNER: float = 0.20

# Max Code Size and Scanning Limits
MAX_CODE_SIZE_BYTES: int = 1024 * 1024   # 1 MB
MAX_CODE_LINES: int = 5000               # 5,000 lines
MAX_AST_DEPTH: int = 100                 # Prevent AST recursion bombs
MAX_CACHE_SIZE: int = 1024               # LRU Cache capacity

# Shannon Entropy Threshold for Secrets Detection (bits per character)
MIN_SECRET_ENTROPY: float = 3.8
MIN_SECRET_LENGTH: int = 16
MAX_SECRET_LENGTH: int = 512

# Redaction configuration
REDACTED_PREVIEW_PREFIX_LEN: int = 4
