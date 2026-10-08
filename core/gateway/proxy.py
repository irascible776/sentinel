import uuid
from typing import AsyncGenerator
import httpx
from core.gateway.config import settings

async def forward_to_upstream(client: httpx.AsyncClient, payload: dict, stream: bool = False):
    """
    Forwards the chat completion payload to the upstream LLM.
    Supports:
      - 'gemini': Google Gemini API via official OpenAI-compatible endpoint
      - 'mock': offline simulated LLM response
      - 'openai': OpenAI API
      - 'ollama': local open-source LLM
    """
    provider = settings.UPSTREAM_PROVIDER.lower()

    if provider == "mock":
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

    if provider == "gemini":
        api_key = settings.GEMINI_API_KEY or settings.UPSTREAM_API_KEY
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not configured in .env. Please set GEMINI_API_KEY=your_key or set UPSTREAM_PROVIDER=mock."
            )

        gemini_model = settings.GEMINI_MODEL
        target_model = payload.get("model")
        # Ensure model is a valid Gemini model, mapping gpt-* defaults to configured Gemini model
        if not target_model or not target_model.startswith("gemini"):
            target_model = gemini_model

        forward_payload = {k: v for k, v in payload.items() if k not in ("session_id", "request_id")}
        forward_payload["model"] = target_model

        base_url = (settings.GEMINI_BASE_URL or "https://generativelanguage.googleapis.com/v1beta/openai").rstrip("/")
        url = f"{base_url}/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }

        if stream:
            req = client.build_request("POST", url, headers=headers, json=forward_payload)
            upstream_res = await client.send(req, stream=True)
            if upstream_res.status_code >= 400:
                await upstream_res.aread()
                try:
                    err_json = upstream_res.json()
                    msg = err_json.get("error", {}).get("message") or upstream_res.text
                except Exception:
                    msg = upstream_res.text
                raise RuntimeError(f"Gemini API error ({upstream_res.status_code}): {msg}")
            return upstream_res
        else:
            response = await client.post(url, headers=headers, json=forward_payload)
            if response.status_code >= 400:
                try:
                    err_json = response.json()
                    msg = err_json.get("error", {}).get("message") or response.text
                except Exception:
                    msg = response.text
                raise RuntimeError(f"Gemini API error ({response.status_code}): {msg}")
            return response.json()

    # Standard OpenAI / Ollama forwarder:
    headers = {
        "Content-Type": "application/json"
    }
    if settings.UPSTREAM_API_KEY:
        headers["Authorization"] = f"Bearer {settings.UPSTREAM_API_KEY}"

    url = f"{settings.UPSTREAM_BASE_URL.rstrip('/')}/chat/completions"

    forward_payload = {k: v for k, v in payload.items() if k not in ("session_id", "request_id")}
    if stream:
        req = client.build_request("POST", url, headers=headers, json=forward_payload)
        upstream_res = await client.send(req, stream=True)
        if upstream_res.status_code >= 400:
            await upstream_res.aread()
            try:
                err_json = upstream_res.json()
                msg = err_json.get("error", {}).get("message") or upstream_res.text
            except Exception:
                msg = upstream_res.text
            raise RuntimeError(f"Upstream API error ({upstream_res.status_code}): {msg}")
        return upstream_res
    else:
        response = await client.post(url, headers=headers, json=forward_payload)
        if response.status_code >= 400:
            try:
                err_json = response.json()
                msg = err_json.get("error", {}).get("message") or response.text
            except Exception:
                msg = response.text
            raise RuntimeError(f"Upstream API error ({response.status_code}): {msg}")
        return response.json()
