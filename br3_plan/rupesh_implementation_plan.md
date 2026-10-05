# Implementation Plan for Developer 2 (Rupesh) - Systems & Gateway Proxy Engineer

This implementation plan is derived from the project architecture and the integration specification to guide Developer 2 (Rupesh) in building the core AI Security Gateway server.

## Overview of Responsibilities
Rupesh is responsible for building a high-performance FastAPI server that acts as a proxy between clients and upstream LLMs. The server will route prompts to Rohit's detection engine, apply Utkarsh's canary tokens, proxy requests, enforce mid-stream SSE circuit breaking, apply output DLP filtering, and log everything to a SQLite database.

---

## Phase 1: Configuration Management
**Target File**: `core/gateway/config.py`

**Tasks**:
1. Implement configuration management using `pydantic-settings` to read environment variables from `.env`.
2. Define the configuration schema including:
   - `GATEWAY_HOST`, `GATEWAY_PORT`, `GATEWAY_DEBUG`, `GATEWAY_ADMIN_KEY`
   - `UPSTREAM_PROVIDER` (`openai` or `ollama` or `mock`), `UPSTREAM_BASE_URL`, `UPSTREAM_API_KEY`, `UPSTREAM_MODEL`
3. Expose a global `settings` object that can be imported across the gateway module.

---

## Phase 2: Database Initialization and ORM
**Target File**: `core/gateway/database.py`

**Tasks**:
1. Set up an asynchronous or synchronous SQLAlchemy engine pointing to `sqlite:///./gateway.db`.
2. **Critical SQLite Fix**: Use `@event.listens_for(engine, "connect")` to execute `PRAGMA journal_mode=WAL;` and `PRAGMA busy_timeout=5000;`. This avoids `database is locked` errors during concurrent access.
3. Define SQLAlchemy models matching the integration spec:
   - `requests`: id, session_id, timestamp, prompt, response, decision, risk_score, latency_ms, agent_breakdown, reasoning, is_stream.
   - `security_events`: id, request_id, session_id, timestamp, event_type, severity, details.
4. Implement helper CRUD functions: `init_db()`, `log_request()`, `log_security_event()`.
5. Implement query functions for the dashboard APIs (stats, recent events, canary alerts).

---

## Phase 3: Upstream LLM Proxy
**Target File**: `core/gateway/proxy.py`

**Tasks**:
1. Implement a function to handle outbound calls using `httpx.AsyncClient`.
2. Support `UPSTREAM_PROVIDER="mock"` for local, cost-free development. Return a dummy response simulating an LLM.
3. For OpenAI/Ollama, appropriately forward headers and body payloads to `UPSTREAM_BASE_URL`.
4. Support both streaming (`stream=True`) and non-streaming requests.

---

## Phase 4: Response-Side DLP Guard (Add-on 6)
**Target File**: `core/gateway/dlp.py`

**Tasks**:
1. Build a `DLPScanner` class/module to inspect full non-streaming text responses.
2. Implement regex matching for PII (emails, phone numbers, credit cards) and API secrets (e.g., `sk-...`).
3. Check for the presence of the active `canary_token` in the response text.
4. If sensitive data or a canary is found, redact the string (e.g., `[REDACTED PII]`) and trigger a log insertion to the `security_events` table with `severity="HIGH"`.

---

## Phase 5: Streaming Circuit Breaker (Add-on 5)
**Target File**: `core/gateway/stream_interceptor.py`

**Tasks**:
1. Implement a generator function `stream(upstream_stream, canary_token)`.
2. Use a sliding window buffer (e.g., holding the last 50 characters). As new tokens yield from the upstream LLM, append them to the buffer.
3. Constantly evaluate the buffer against the canary token and critical leak patterns.
4. **Circuit Breaker Logic**: If a leak is detected mid-stream:
   - Do NOT abruptly drop the connection.
   - Yield a delta replacing the remaining output: `data: {"choices": [{"delta": {"content": "\n[RESPONSE TERMINATED DUE TO POLICY VIOLATION]"}}]}\n\n`
   - Yield `data: [DONE]\n\n` and `return` to close the generator gracefully.
   - Write to the `security_events` database log.

---

## Phase 6: The FastAPI Application & REST APIs
**Target File**: `core/gateway/app.py`

**Tasks**:
1. **App Initialization**: Create the FastAPI app with `CORSMiddleware` (`allow_origins=["*"]`).
2. **Lifespan**: Use `@asynccontextmanager` to call `init_db()` and initialize `app.state.http_client = httpx.AsyncClient()`.
3. **Module Wiring**: Import and instantiate Rohit's `JudgeAgent` and Utkarsh's `CanaryEngine`.
4. **Primary Endpoint** (`POST /v1/chat/completions`):
   - Extract `session_id` and the latest user prompt.
   - Call `judge.evaluate()`. If `BLOCK`, return HTTP 403 Forbidden with the required error schema.
   - If `ALLOW`, call `canary_engine.inject_into_prompt()`.
   - Forward to upstream using `proxy.py`.
   - If `stream=True`, return `StreamingResponse` wrapping `stream_interceptor.stream()`.
   - If `stream=False`, wait for response, pass through `dlp.scan()`, and return.
   - Call `database.log_request()` asynchronously or via background tasks.
5. **Inspection Endpoint** (`POST /api/v1/inspect`): 
   - Accepts prompts, runs `judge.evaluate()`, and returns the verdict directly for the Chrome extension.
6. **Telemetry API Endpoints**:
   - `GET /api/v1/stats`, `GET /api/v1/events`, `GET /api/v1/canary-alerts`, `GET /api/v1/rules`.
   - `POST /api/v1/threat-intel/run` (Imports and calls `ThreatIntelligenceFeed.run_clustering_and_update()`).
