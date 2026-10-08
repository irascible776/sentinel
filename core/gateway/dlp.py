import re
from core.gateway.database import log_security_event

class DLPScanner:
    def __init__(self):
        # Basic patterns for PII and Secrets
        self.patterns = {
            "EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
            "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
            "OPENAI_KEY": re.compile(r"sk-[a-zA-Z0-9]{48}"),
            "GEMINI_KEY": re.compile(r"AIzaSy[0-9A-Za-z-_]{33}"),
            "AWS_KEY": re.compile(r"AKIA[0-9A-Z]{16}")
        }

    def scan(self, response_text: str, canary_token: str, session_id: str, request_id: str = None) -> str:
        """
        Scans the full response text for PII, secrets, and canary token leakage.
        Redacts found information and logs a security event if necessary.
        """
        redacted_text = response_text
        has_leak = False
        leaked_details = {}

        # 1. Check for Canary Token
        if canary_token and canary_token in redacted_text:
            redacted_text = redacted_text.replace(canary_token, "[REDACTED CANARY TOKEN]")
            has_leak = True
            leaked_details["CANARY"] = "Canary token leaked in response."

        # 2. Check for PII and Secrets
        for label, pattern in self.patterns.items():
            matches = pattern.findall(redacted_text)
            if matches:
                has_leak = True
                leaked_details[label] = f"Found {len(matches)} instance(s) of {label}."
                redacted_text = pattern.sub(f"[REDACTED {label}]", redacted_text)

        if has_leak:
            is_canary = "CANARY" in leaked_details
            log_security_event(
                session_id=session_id,
                event_type="CANARY_EXFILTRATION" if is_canary else "DATA_EXFILTRATION_PREVENTED",
                severity="CRITICAL" if is_canary else "HIGH",
                details={
                    "leaked_patterns": leaked_details,
                    "canary_token": canary_token if is_canary else None,
                    "action_taken": "RESPONSE_REDACTED"
                },
                request_id=request_id
            )

        return redacted_text

dlp_scanner = DLPScanner()
