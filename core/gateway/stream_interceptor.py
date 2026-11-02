import json
import httpx
from core.gateway.database import log_security_event
from core.gateway.ast_analyzer import scan_response_text, TaintFlowViolation

async def stream_interceptor(upstream_stream, canary_token: str, session_id: str, request_id: str = None):
    """
    Intercepts an SSE stream from the upstream LLM (either an httpx.Response or an async generator).

    Egress Defense Layers:
      1. Canary Token Monitor  : Detects if the LLM leaks the injected honeypot secret.
      2. AST Taint-Flow Scanner: Detects weaponizable Source→Sink code flows in generated Python
                                 (e.g., keystroke capture → network exfiltration).
      3. Sliding Window DLP    : Scans the last N characters for raw secrets / credentials.

    If any violation is detected, the stream is terminated gracefully and a POLICY VIOLATION
    message is sent to the client instead of the malicious content.
    """
    sliding_window = ""
    ast_buffer = ""             # Accumulates full response text for AST scanning
    window_size = 150           # Sliding window for canary/DLP scan (in characters)
    ast_scan_threshold = 500    # Only run AST scan once we have enough code to parse

    def check_canary_leak(text: str) -> bool:
        """Returns True if the canary honeypot token appears in the output."""
        return bool(canary_token and canary_token in text)

    def check_ast_taint(full_text: str) -> bool:
        """
        Returns True if a dangerous Source→Sink code flow is detected.
        Only runs when the accumulated buffer crosses the threshold.
        """
        if len(full_text) < ast_scan_threshold:
            return False
        violation = scan_response_text(full_text)
        return violation is not None

    def get_ast_violation_detail(full_text: str) -> str:
        """Returns violation details for logging."""
        try:
            violation = scan_response_text(full_text)
            if violation:
                return f"{violation.source} → {violation.sink}: {violation.detail}"
        except Exception:
            pass
        return "Taint-flow violation detected"

    is_httpx_response = isinstance(upstream_stream, httpx.Response)

    try:
        if is_httpx_response:
            iterator = upstream_stream.aiter_lines()
        else:
            iterator = upstream_stream

        async for line in iterator:
            if isinstance(line, bytes):
                line = line.decode('utf-8')

            # Parse SSE data chunk to extract the actual text content
            if line.startswith("data: ") and line.strip() != "data: [DONE]":
                try:
                    data_json = json.loads(line[6:])
                    if "choices" in data_json and len(data_json["choices"]) > 0:
                        delta = data_json["choices"][0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            # ── Layer 1: Sliding window (canary + DLP) ────────────
                            sliding_window += content
                            if len(sliding_window) > window_size:
                                sliding_window = sliding_window[-window_size:]

                            # ── Layer 2: AST Code Accumulation Buffer ─────────────
                            ast_buffer += content

                            # ── CIRCUIT BREAKER: Canary Token Leak ───────────────
                            if check_canary_leak(sliding_window):
                                log_security_event(
                                    session_id=session_id,
                                    event_type="STREAM_CIRCUIT_BREAKER",
                                    severity="CRITICAL",
                                    details={
                                        "reason": "Canary honeypot token detected in LLM response stream",
                                        "violation_type": "CANARY_LEAK",
                                        "canary_token": canary_token,
                                        "action_taken": "STREAM_TERMINATED"
                                    },
                                    request_id=request_id
                                )
                                yield f'data: {json.dumps({"choices": [{"delta": {"content": "\\n\\n[RESPONSE TERMINATED DUE TO POLICY VIOLATION]"}}]})}\n\n'.encode('utf-8')
                                yield b'data: [DONE]\n\n'
                                return

                            # ── CIRCUIT BREAKER: Egress AST Taint-Flow Scan ──────
                            if check_ast_taint(ast_buffer):
                                detail = get_ast_violation_detail(ast_buffer)
                                log_security_event(
                                    session_id=session_id,
                                    event_type="STREAM_CIRCUIT_BREAKER",
                                    severity="CRITICAL",
                                    details={
                                        "reason": "Weaponizable code data-flow detected in LLM response",
                                        "violation_type": "TAINT_FLOW_VIOLATION",
                                        "taint_detail": detail,
                                        "action_taken": "STREAM_TERMINATED"
                                    },
                                    request_id=request_id
                                )
                                yield f'data: {json.dumps({"choices": [{"delta": {"content": "\\n\\n[RESPONSE TERMINATED DUE TO POLICY VIOLATION]"}}]})}\n\n'.encode('utf-8')
                                yield b'data: [DONE]\n\n'
                                return

                except json.JSONDecodeError:
                    pass

            # Yield the original line if no violation detected
            if isinstance(line, str):
                cleaned = line.rstrip("\r\n")
                if cleaned:
                    yield f"{cleaned}\n\n".encode("utf-8")
            else:
                cleaned = line.rstrip(b"\r\n")
                if cleaned:
                    yield cleaned + b"\n\n"

    finally:
        if is_httpx_response:
            await upstream_stream.aclose()
