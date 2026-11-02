"""
High-Entropy Secret Scanner & Credential Detector (CWE-798)
Combines Shannon entropy analysis on string assignments with verified structural regex matching
for AWS credentials, GitHub tokens, JWTs, and private keys. Enforces strict redaction.
"""

import re
import math
import base64
import json
import hashlib
from typing import List, Tuple, Optional, Set
from collections import Counter

from core.codesec.config import (
    MIN_SECRET_ENTROPY,
    MIN_SECRET_LENGTH,
    MAX_SECRET_LENGTH,
    REDACTED_PREVIEW_PREFIX_LEN,
)
from core.codesec.schemas import SecretMatch, VulnerabilityFinding, ScanSourceEnum


# Verified Structural Signatures
AWS_KEY_PATTERN = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
GITHUB_PAT_PATTERN = re.compile(r"\b(gh[pousr]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b")
PEM_KEY_PATTERN = re.compile(r"-----BEGIN ([A-Z ]+)?PRIVATE KEY(?: BLOCK)?-----")
JWT_PATTERN = re.compile(r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")

# Assignment pattern for sensitive variable names (word-bounded, supports JSON quotes and .env)
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"""(?xi)
    ["']?\b(?:[a-zA-Z0-9_]*_)?(?:api_?key|secret_?key|private_?key|secret|token|auth_?token|client_?secret|password|passwd|credentials?|access_?key)[a-zA-Z0-9_]*["']?
    \s*[:=]\s*
    ["']?([^"'\s]{10,512})["']?
    """
)

# Known false positive values / documentation examples (stored lowercase)
FALSE_POSITIVE_PLACEHOLDERS: Set[str] = {
    "your_api_key_here",
    "your_secret_key_here",
    "replace_with_your_token",
    "changeme",
    "password123",
    "admin12345",
    "example_key",
    "dummy_secret",
    "xxxxxxxxxxxxxxxx",
    "0000000000000000",
    "akiaiosfodnn7example",  # Official AWS documentation sample key
}

SECRET_SALT: str = "sentinel_fp_salt_v2"


def calculate_string_entropy(text: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder_secret(secret: str) -> bool:
    """Checks if secret candidate is a known dummy placeholder or documentation example."""
    lower = secret.strip().lower()
    if lower in FALSE_POSITIVE_PLACEHOLDERS:
        return True
    if any(placeholder in lower for placeholder in ["your_key", "your_secret", "dummy", "placeholder", "changeme"]):
        return True
    if lower.endswith("example") or "examplekey" in lower:
        return True
    # UUID check (8-4-4-4-12 hex)
    if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", lower):
        return True
    # URL check
    if lower.startswith(("http://", "https://", "ftp://")):
        return True
    # Template references
    if lower.startswith(("${", "{{", "<")) or lower.endswith(("}", ">")):
        return True
    # All identical characters (e.g. 'aaaaaaaaaaaaaaaa')
    if len(set(lower)) <= 2:
        return True
    return False


def is_valid_jwt(token: str) -> bool:
    """Verifies that a JWT-like string has a valid Base64URL header containing JSON with 'alg'."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header_b64 = parts[0]
        # Pad Base64 if needed
        padding = len(header_b64) % 4
        if padding != 0:
            header_b64 += "=" * (4 - padding)
        decoded = base64.urlsafe_b64decode(header_b64).decode("utf-8", errors="ignore")
        data = json.loads(decoded)
        return isinstance(data, dict) and "alg" in data
    except Exception:
        return False


def redact_secret(secret: str) -> str:
    """Never returns raw secrets. Returns a safe prefix plus a salted 12-char SHA-256 fingerprint."""
    if any(secret.startswith(p) for p in ("AKIA", "ASIA", "ghp_", "gho_", "ghs_", "ghu_", "ghr_", "eyJ")):
        prefix = secret[:4]
    else:
        prefix = secret[:min(2, max(1, len(secret) // 4))]
    digest = hashlib.sha256((secret + SECRET_SALT).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}***[sha256:{digest}]"


class SecretScanner:
    """
    High-Entropy and Structural Secret Scanner for source code.
    Identifies hard-coded credentials, private keys, API tokens, and JWTs.
    """

    def scan_code(self, code: str) -> Tuple[List[SecretMatch], List[VulnerabilityFinding]]:
        secrets: List[SecretMatch] = []
        findings: List[VulnerabilityFinding] = []
        lines = code.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            is_comment = stripped.startswith(("#", "//", "/*", "*"))

            # 1. AWS Key Check (Tier 1 Verified Structure - scans comments too)
            aws_matches = AWS_KEY_PATTERN.findall(line)
            for match in aws_matches:
                if not is_placeholder_secret(match):
                    entropy = calculate_string_entropy(match)
                    redacted = redact_secret(match)
                    secrets.append(SecretMatch(
                        kind="AWS Access Key ID",
                        line=idx,
                        entropy=round(entropy, 2),
                        verified_structure=True,
                        redacted_preview=redacted,
                    ))
                    findings.append(VulnerabilityFinding(
                        cwe="CWE-798",
                        title="Hard-coded AWS Access Key",
                        line_start=idx,
                        line_end=idx,
                        confidence=0.99,
                        tier=1,
                        source=ScanSourceEnum.SECRET,
                        evidence=f"AWS key detected on line {idx}: {redacted}",
                        remediation="Revoke key immediately and move credentials to AWS Secrets Manager or environment variables.",
                    ))

            # 2. GitHub Token Check (Tier 1 Verified Structure)
            gh_matches = GITHUB_PAT_PATTERN.findall(line)
            for match in gh_matches:
                if not is_placeholder_secret(match):
                    entropy = calculate_string_entropy(match)
                    redacted = redact_secret(match)
                    secrets.append(SecretMatch(
                        kind="GitHub Personal Access Token",
                        line=idx,
                        entropy=round(entropy, 2),
                        verified_structure=True,
                        redacted_preview=redacted,
                    ))
                    findings.append(VulnerabilityFinding(
                        cwe="CWE-798",
                        title="Hard-coded GitHub Token",
                        line_start=idx,
                        line_end=idx,
                        confidence=0.99,
                        tier=1,
                        source=ScanSourceEnum.SECRET,
                        evidence=f"GitHub token on line {idx}: {redacted}",
                        remediation="Revoke GitHub token and store in GitHub Actions Secrets or a secure key vault.",
                    ))

            # 3. PEM Private Key (Tier 1 Verified Structure)
            if PEM_KEY_PATTERN.search(line):
                redacted = "-----BEGIN PRIVATE KEY...[REDACTED]"
                secrets.append(SecretMatch(
                    kind="Asymmetric Private Key (PEM)",
                    line=idx,
                    entropy=4.5,
                    verified_structure=True,
                    redacted_preview=redacted,
                ))
                findings.append(VulnerabilityFinding(
                    cwe="CWE-798",
                    title="Hard-coded Cryptographic Private Key",
                    line_start=idx,
                    line_end=idx,
                    confidence=1.0,
                    tier=1,
                    source=ScanSourceEnum.SECRET,
                    evidence=f"Private key header on line {idx}",
                    remediation="Never commit private keys to source code. Store in KMS or HSM.",
                ))

            # 4. JWT Token Check (Tier 1 Verified Structure)
            jwt_matches = JWT_PATTERN.findall(line)
            for match in jwt_matches:
                if is_valid_jwt(match) and not is_placeholder_secret(match):
                    entropy = calculate_string_entropy(match)
                    redacted = redact_secret(match)
                    secrets.append(SecretMatch(
                        kind="JSON Web Token (JWT)",
                        line=idx,
                        entropy=round(entropy, 2),
                        verified_structure=True,
                        redacted_preview=redacted,
                    ))
                    findings.append(VulnerabilityFinding(
                        cwe="CWE-798",
                        title="Hard-coded JSON Web Token (JWT)",
                        line_start=idx,
                        line_end=idx,
                        confidence=0.95,
                        tier=1,
                        source=ScanSourceEnum.SECRET,
                        evidence=f"JWT on line {idx}: {redacted}",
                        remediation="Obtain JWTs dynamically from authentication providers; do not hardcode in source.",
                    ))

            # 5. Sensitive Variable Assignment with Shannon Entropy Analysis (Tier 3)
            if is_comment:
                continue

            assignment_matches = SENSITIVE_ASSIGNMENT_PATTERN.finditer(line)
            for m in assignment_matches:
                assigned_val = m.group(1).strip()
                redacted = redact_secret(assigned_val)
                # Skip if already captured by higher-precedence structural pattern on this line
                if any(s.line == idx and s.redacted_preview == redacted for s in secrets):
                    continue

                if (
                    len(assigned_val) >= MIN_SECRET_LENGTH
                    and len(assigned_val) <= MAX_SECRET_LENGTH
                    and not is_placeholder_secret(assigned_val)
                ):
                    entropy = calculate_string_entropy(assigned_val)
                    if entropy >= MIN_SECRET_ENTROPY:
                        secrets.append(SecretMatch(
                            kind="High-Entropy Credential Assignment",
                            line=idx,
                            entropy=round(entropy, 2),
                            verified_structure=False,
                            redacted_preview=redacted,
                        ))
                        findings.append(VulnerabilityFinding(
                            cwe="CWE-798",
                            title="High-Entropy Credential Assignment",
                            line_start=idx,
                            line_end=idx,
                            confidence=0.75,
                            tier=3,
                            source=ScanSourceEnum.SECRET,
                            evidence=f"Sensitive variable assignment on line {idx} (Shannon entropy: {entropy:.2f}): {redacted}",
                            remediation="Inject sensitive secrets from environment variables or a secrets manager.",
                        ))

        return secrets, findings
