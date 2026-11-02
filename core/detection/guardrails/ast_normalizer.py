"""
Sentinel v2.0 — Pillar IV: AST Normalizer & Recursive De-Obfuscator
Preprocesses and unrolls obfuscated agent tool arguments before inspection.
Detects stacked queries, shell delimiters, base64 payloads, and GTFOBins patterns.
"""

import re
import base64
import urllib.parse
from typing import Tuple, Optional, Any


class PayloadNormalizer:
    # High-risk command execution & reverse shell patterns
    # High-risk command execution & reverse shell patterns
    REVERSE_SHELL_PATTERNS = [
        re.compile(r"/dev/(tcp|udp)/[a-zA-Z0-9_.-]+/\d+", re.IGNORECASE | re.DOTALL),
        re.compile(r"(nc|ncat)\s+.*(-e|-c)\s+(/bin/)?(ba|z|da|k)?sh", re.IGNORECASE | re.DOTALL),
        re.compile(r"mkfifo\s+.*;\s*cat\s+.*\|", re.IGNORECASE | re.DOTALL),
        re.compile(r"\|\s*(/bin/)?(ba|z|da|k)?sh\b", re.IGNORECASE | re.DOTALL),
        re.compile(r"base64\s+(-d|--decode)\s*\|\s*(/bin/)?(ba|z|da|k)?sh", re.IGNORECASE | re.DOTALL),
        re.compile(r"(curl|wget|fetch|nc)\s+.*169\.254\.169\.254", re.IGNORECASE | re.DOTALL),
        re.compile(r"python[23]?\s+-c\s+.*(pty\.spawn|socket\.socket)", re.IGNORECASE | re.DOTALL),
        re.compile(r"(perl|ruby|php|node)\s+(-e|-r)\s+.*(exec|system|fsockopen|net\.Socket)", re.IGNORECASE | re.DOTALL),
        re.compile(r"socat\s+exec:.*tcp:", re.IGNORECASE | re.DOTALL),
    ]

    # High-risk GTFOBins living-off-the-land commands
    GTFOBINS_FLAGS = [
        re.compile(r"find\s+.*-(exec|execdir)\s+(/bin/)?(ba|z|da|k)?sh", re.IGNORECASE | re.DOTALL),
        re.compile(r"awk\s+['\"].*system\(.*\)['\"]", re.IGNORECASE | re.DOTALL),
        re.compile(r"tar\s+.*--checkpoint-action=exec", re.IGNORECASE | re.DOTALL),
        re.compile(r"git\s+.*core\.sshCommand", re.IGNORECASE | re.DOTALL),
        re.compile(r"env\s+(/bin/)?(ba|z|da|k)?sh", re.IGNORECASE | re.DOTALL),
    ]

    # Destructive / Privileged SQL operations disguised in tools
    DESTRUCTIVE_SQL = [
        re.compile(r"(^|;)\s*DROP\s+TABLE", re.IGNORECASE | re.DOTALL),
        re.compile(r"(^|;)\s*TRUNCATE\s+TABLE", re.IGNORECASE | re.DOTALL),
        re.compile(r"(^|;)\s*ALTER\s+TABLE", re.IGNORECASE | re.DOTALL),
        re.compile(r";\s*DELETE\s+FROM", re.IGNORECASE | re.DOTALL),
        re.compile(r"xp_cmdshell", re.IGNORECASE | re.DOTALL),
        re.compile(r"COPY\s+.*(TO|FROM)\s+PROGRAM", re.IGNORECASE | re.DOTALL),
        re.compile(r"INTO\s+(OUTFILE|DUMPFILE)", re.IGNORECASE | re.DOTALL),
        re.compile(r"pg_sleep\s*\(\s*\d+(\.\d+)?\s*\)", re.IGNORECASE | re.DOTALL),
        re.compile(r"(sleep|benchmark)\s*\(\s*\d+", re.IGNORECASE | re.DOTALL),
        re.compile(r"WAITFOR\s+DELAY\s+['\"]\d+:\d+:\d+['\"]", re.IGNORECASE | re.DOTALL),
        re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE | re.DOTALL),
    ]

    @classmethod
    def deobfuscate(cls, text: str) -> str:
        """Recursively decodes URL-encoding, hex escapes, base64 strings, and normalizes ${IFS}."""
        if not text:
            return ""

        # 1. URL decoding (up to 2 passes for double-encoding)
        decoded = urllib.parse.unquote(text)
        if "%" in decoded:
            decoded = urllib.parse.unquote(decoded)

        # 2. Normalize ${IFS} or $IFS shell whitespace evasions
        decoded = re.sub(r"\$\{IFS\}|\$IFS(\$9)?", " ", decoded)

        # 3. Decode \xHH hex byte sequences
        def replace_hex(match):
            try:
                return bytes.fromhex(match.group(1)).decode('utf-8', errors='ignore')
            except Exception:
                return match.group(0)
        decoded = re.sub(r"\\x([0-9a-fA-F]{2})", replace_hex, decoded)

        # 4. Search and decode standalone Base64 blocks (len >= 8)
        b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
        for match in b64_pattern.finditer(decoded):
            candidate = match.group(0)
            if len(candidate) >= 8:
                try:
                    raw_bytes = base64.b64decode(candidate)
                    decoded_candidate = raw_bytes.decode('utf-8')
                    # If decoded content looks like ASCII text with shell/SQL keywords
                    if any(k in decoded_candidate for k in ["/bin", "sh", "cat", "id", "whoami", "SELECT", "UNION", "curl", "wget", "rm "]):
                        decoded += f" [DECODED_BASE64: {decoded_candidate}]"
                except Exception:
                    pass

        return decoded

    MAX_INPUT_LENGTH = 65_536  # 64 KB cap to prevent ReDoS / CPU starvation

    @classmethod
    def inspect(cls, raw_payload: str) -> Tuple[str, Optional[str]]:
        """
        Normalizes the payload and runs deterministic security heuristics.
        Fails closed on oversized inputs to prevent padding bypasses.
        Returns:
            normalized_payload: str
            threat_reason: Optional[str] if hard-blocked deterministically
        """
        if not isinstance(raw_payload, str):
            raw_payload = str(raw_payload)

        # Strict fail-closed on oversized inputs to prevent padding evasion (Claude C1)
        if len(raw_payload) > cls.MAX_INPUT_LENGTH:
            return raw_payload[:256], f"Payload length ({len(raw_payload)} bytes) exceeds 64KB threshold (padding/DoS evasion blocked)"

        normalized = cls.deobfuscate(raw_payload)

        # Check reverse shells & IMDS exfiltration
        for pat in cls.REVERSE_SHELL_PATTERNS:
            if pat.search(normalized):
                return normalized, "Interactive reverse shell or network redirect detected"

        # Check GTFOBins living-off-the-land commands
        for pat in cls.GTFOBINS_FLAGS:
            if pat.search(normalized):
                return normalized, "GTFOBins living-off-the-land shell escape detected"

        # Check destructive SQL / Out-of-band / Time-based injection
        for pat in cls.DESTRUCTIVE_SQL:
            if pat.search(normalized):
                return normalized, "Destructive/Time-based stacked SQL injection detected"

        # Check path traversal attempts
        if any(p in normalized for p in ["../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/self/", "~/.ssh", ".aws/credentials", ".env"]):
            return normalized, "Directory traversal / sensitive file access detected"

        return normalized, None


def iter_strings(data: Any) -> list:
    """Recursively extracts all string values from nested dictionaries, lists, or scalars."""
    found = []
    if isinstance(data, str):
        found.append(data)
    elif isinstance(data, dict):
        for v in data.values():
            found.extend(iter_strings(v))
    elif isinstance(data, (list, tuple, set)):
        for item in data:
            found.extend(iter_strings(item))
    elif data is not None:
        found.append(str(data))
    return found
