import json
import httpx
from core.gateway.database import log_security_event

async def stream_interceptor(upstream_stream, canary_token: str, session_id: str, request_id: str = None):
    """
    Intercepts an SSE stream from the upstream LLM (either an httpx.Response or an async generator).
    Maintains a sliding window buffer to detect canary tokens or sensitive leaks mid-stream.
    If a leak is detected, terminates the stream gracefully.
    """
    sliding_window = ""
    window_size = 50 # Keep the last 50 characters in memory
    
    # helper to check leaks
    def check_leak(text: str) -> bool:
        if canary_token and canary_token in text:
            return True
        # Basic secret pattern checks could also be added here, similar to DLP
        return False

    is_httpx_response = isinstance(upstream_stream, httpx.Response)

    try:
        if is_httpx_response:
            iterator = upstream_stream.aiter_lines()
        else:
            iterator = upstream_stream
        
        async for line in iterator:
            if isinstance(line, bytes):
                line = line.decode('utf-8')

            # Parse SSE data chunk to extract the actual text content for the sliding window
            if line.startswith("data: ") and line.strip() != "data: [DONE]":
                try:
                    data_json = json.loads(line[6:])
                    if "choices" in data_json and len(data_json["choices"]) > 0:
                        delta = data_json["choices"][0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            sliding_window += content
                            if len(sliding_window) > window_size:
                                sliding_window = sliding_window[-window_size:]
                            
                            # Check for leak
                            if check_leak(sliding_window):
                                # Leak detected! Trigger circuit breaker
                                log_security_event(
                                    session_id=session_id,
                                    event_type="STREAM_CIRCUIT_BREAKER",
                                    severity="CRITICAL",
                                    details={"reason": "Canary token or sensitive secret detected in stream"},
                                    request_id=request_id
                                )
                                # Send termination payload
                                yield f'data: {json.dumps({"choices": [{"delta": {"content": "\\n\\n[RESPONSE TERMINATED DUE TO POLICY VIOLATION]"}}]})}\n\n'.encode('utf-8')
                                yield b'data: [DONE]\n\n'
                                return # Cleanly exit the generator
                except json.JSONDecodeError:
                    pass
            
            # Yield the original line if no leak detected
            if isinstance(line, str):
                yield (line + "\n").encode('utf-8')
            else:
                yield line + b"\n"
    
    finally:
        if is_httpx_response:
            await upstream_stream.aclose()
