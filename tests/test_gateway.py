import pytest
import httpx
from httpx import AsyncClient, ASGITransport
from core.gateway.app import app
from core.gateway.database import init_db

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.mark.asyncio
async def test_inspect_clean_prompt():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/inspect", json={
            "prompt": "Hello, how are you?",
            "session_id": "test-session"
        })
    assert response.status_code == 200
    data = response.json()
    # JudgeAgent is mocked/dummy right now, so it should just return ALLOW or something.
    assert "decision" in data

@pytest.mark.asyncio
async def test_stats_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_prompts" in data
    assert "allowed_count" in data

@pytest.mark.asyncio
async def test_chat_completions_clean():
    app.state.http_client = httpx.AsyncClient(transport=ASGITransport(app=app))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/v1/chat/completions", json={
            "session_id": "test-session",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False
        })
    assert response.status_code == 200
    data = response.json()
    assert "choices" in data
    assert "security_metadata" in data
    assert data["security_metadata"]["decision"] == "ALLOW"

