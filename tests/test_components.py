import pytest

@pytest.mark.asyncio
async def test_dlp_scanner():
    from core.gateway.dlp import dlp_scanner
    text = "Here is my email test@example.com and key sk-123456789012345678901234567890123456789012345678"
    result = dlp_scanner.scan(text, "CANARY-123", "sess-1")
    assert "[REDACTED EMAIL]" in result
    assert "[REDACTED OPENAI_KEY]" in result
    assert "test@example.com" not in result

@pytest.mark.asyncio
async def test_stream_interceptor_circuit_breaker():
    from core.gateway.stream_interceptor import stream_interceptor
    import json

    async def dummy_upstream_stream():
        yield b'data: {"choices": [{"delta": {"content": "Hello, "}}]}\n\n'
        yield b'data: {"choices": [{"delta": {"content": "this is "}}]}\n\n'
        yield b'data: {"choices": [{"delta": {"content": "CANARY-SECRET-123"}}]}\n\n'
        yield b'data: {"choices": [{"delta": {"content": " leaked."}}]}\n\n'
        yield b'data: [DONE]\n\n'

    generator = stream_interceptor(dummy_upstream_stream(), "CANARY-SECRET-123", "sess-1")
    chunks = [chunk async for chunk in generator]
    output = b"".join(chunks).decode("utf-8")
    assert "[RESPONSE TERMINATED DUE TO POLICY VIOLATION]" in output
    assert " leaked." not in output
