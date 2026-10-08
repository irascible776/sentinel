import uuid
from typing import AsyncGenerator
import httpx
from core.gateway.config import settings

async def forward_to_upstream(client: httpx.AsyncClient, payload: dict, stream: bool = False):
    """
    Forwards the chat completion payload to the upstream LLM.
    Returns a dummy response if UPSTREAM_PROVIDER is 'mock'.
    """
    if settings.UPSTREAM_PROVIDER.lower() == "mock":
        if stream:
            async def mock_stream() -> AsyncGenerator[bytes, None]:
                yield b'data: {"choices": [{"delta": {"content": "I "}}]}\n\n'
                yield b'data: {"choices": [{"delta": {"content": "am "}}]}\n\n'
                yield b'data: {"choices": [{"delta": {"content": "a "}}]}\n\n'
                yield b'data: {"choices": [{"delta": {"content": "mock "}}]}\n\n'
                yield b'data: {"choices": [{"delta": {"content": "response."}}]}\n\n'
                yield b'data: [DONE]\n\n'
            return mock_stream()
        else:
            return {
                "id": f"mock-cmpl-{uuid.uuid4().hex[:8]}",
                "object": "chat.completion",
                "model": payload.get("model", settings.UPSTREAM_MODEL),
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "I am a secure AI assistant. Your prompt was verified safe."
                    },
                    "finish_reason": "stop"
                }]
            }

    # Prepare headers for actual request
    headers = {
        "Content-Type": "application/json"
    }
    if settings.UPSTREAM_API_KEY:
        headers["Authorization"] = f"Bearer {settings.UPSTREAM_API_KEY}"

    # Target URL
    url = f"{settings.UPSTREAM_BASE_URL.rstrip('/')}/chat/completions"

    if stream:
        req = client.build_request("POST", url, headers=headers, json=payload)
        return await client.send(req, stream=True)
    else:
        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
