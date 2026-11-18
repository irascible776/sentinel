# 02 Request Lifecycle & Proxy Architecture

## 1. End-to-End Step-by-Step Lifecycle

The primary entry point for proxy traffic is `POST /v1/chat/completions` implemented in `sentinel/core/gateway/app.py` [VERIFIED sentinel/core/gateway/app.py:101-325].

### Step 1: Ingress Parsing & Session Resolution
1. **Timestamping**: Starts performance clock with `t_start = time.perf_counter()` [VERIFIED sentinel/core/gateway/app.py:103].
2. **Payload Decode**: Parses request body using `await request.json()`. On JSON syntax failure, immediately raises `HTTPException(status_code=400, detail="Invalid JSON payload")` [VERIFIED sentinel/core/gateway/app.py:105-107].
3. **Session ID Resolution**: Resolves session ID in hierarchical order [VERIFIED sentinel/core/gateway/app.py:110-115]:
   - `payload.get("session_id")`
   - `request.headers.get("x-session-id")`
   - `request.cookies.get("sentinel_sid")`
   - Fallback: generated ephemeral ID `f"sess-{uuid.uuid4().hex[:12]}"`
4. **Content Extraction**: Iterates over `payload.get("messages", [])` to locate `role == "user"`. Handles both plain string content and structured multimodal arrays (`type: "text"` and `type: "image_url"`) [VERIFIED sentinel/core/gateway/app.py:120-149].
5. **Anti-SSRF Inline Image Enforcement**: If `image_url` is an external `http://` or `https://` link, the gateway rejects the request with HTTP 400 (`REMOTE_IMAGE_URL_UNSUPPORTED`) to prevent Server-Side Request Forgery and Time-of-Check to Time-of-Use (TOCTOU) attacks, requiring inline base64 data URIs [VERIFIED sentinel/core/gateway/app.py:142-148].

### Step 2: Multimodal Visual Inspection (Pillar III)
- If base64 image bytes are present, dispatches to `vision_engine.scan_image(img_b, "multimodal_upload.png")` inside `await asyncio.to_thread(...)` [VERIFIED sentinel/core/gateway/app.py:152-154].
- If `img_res.policy_action == VisionPolicyActionEnum.BLOCK`: logs the incident asynchronously via `background_tasks.add_task(log_request, ...)` and returns HTTP 403 `MULTIMODAL_THREAT_BLOCKED` [VERIFIED sentinel/core/gateway/app.py:155-181].
- If image is clean, raw extracted OCR text (`img_res.ocr_analysis.raw_text`) is merged into `user_text` under `[IMAGE_OCR_TEXT]: ...` for subsequent textual inspection [VERIFIED sentinel/core/gateway/app.py:182-184].

### Step 3: Cascaded Ingress Prompt Evaluation
- Invokes `JudgeAgent.evaluate(prompt=user_text, session_id=session_id)` via `asyncio.to_thread` wrapped in a strict timeout [VERIFIED sentinel/core/gateway/app.py:190-194]:
  ```python
  verdict = await asyncio.wait_for(
      asyncio.to_thread(judge.evaluate, prompt=user_text, session_id=session_id),
      timeout=10.0
  )
  ```
- **Timeout Fallback (Fail-Secure)**: On `asyncio.TimeoutError`, executes `fast_scan = judge.pattern_hunter.scan(user_text)` and returns a synthetic verdict with `decision: "BLOCK"`, `risk_score: 85.0`, `confidence: 0.5`, enforcing perimeter fail-secure security [VERIFIED sentinel/core/gateway/app.py:195-210].
- **Exception Fallback (Fail-Secure)**: On any unexpected exception `e`, catches the error, runs `fast_scan = judge.pattern_hunter.scan(user_text)`, and returns `decision: "BLOCK"`, `risk_score: 85.0` [VERIFIED sentinel/core/gateway/app.py:211-226].

### Step 4: Policy Enforcement (Ingress Gate)
- If `verdict["decision"] == "BLOCK"`:
  - Dispatches non-blocking database write via `background_tasks.add_task(log_request, ...)` [VERIFIED sentinel/core/gateway/app.py:234-246].
  - Returns HTTP 403 `JSONResponse` containing error code `PROMPT_INJECTION_BLOCKED`, risk score, agent breakdown, reasoning, and matched signatures [VERIFIED sentinel/core/gateway/app.py:247-258].

### Step 5: System Prompt Honeytoken Instrumentation
- For clean prompts (`ALLOW` or `FLAG`), calls `canary_engine.inject_into_prompt(messages, session_id)` [VERIFIED sentinel/core/gateway/app.py:260-262].
- Injects a unique canary string formatted as `CANARY-SECRET-<uuid>` into the `system` message prompt [VERIFIED sentinel/core/security_vectors/canary.py:15-43].

### Step 6: Upstream Forwarding
- Retrieves pooled `httpx.AsyncClient` from `app.state.http_client` (or initializes temporary client with 30s timeout) [VERIFIED sentinel/core/gateway/app.py:265-270].
- Calls `forward_to_upstream(client, payload, stream=stream)` in `sentinel/core/gateway/proxy.py:6-120` [VERIFIED sentinel/core/gateway/app.py:272].
- Targets provider based on `UPSTREAM_PROVIDER` ("gemini", "mock", "openai", "ollama") [VERIFIED sentinel/core/gateway/proxy.py:15-120].
- On network or provider failure, raises `HTTPException(status_code=502, detail=f"Upstream provider error: {str(e)}")` [VERIFIED sentinel/core/gateway/app.py:273-276].

### Step 7: Egress Inspection & Response Delivery

#### Path A: Streaming (`stream=True`)
- Wraps upstream stream in `stream_interceptor(upstream_response, canary_token, session_id, request_id)` [VERIFIED sentinel/core/gateway/app.py:280-283].
- Returns FastAPI `StreamingResponse(..., media_type="text/event-stream")` [VERIFIED sentinel/core/gateway/app.py:280-283].
- Inside `stream_interceptor`:
  - Iterates over SSE lines using `upstream_stream.aiter_lines()` [VERIFIED sentinel/core/gateway/stream_interceptor.py:52-56].
  - Extracts delta content from `data: {...}` chunks [VERIFIED sentinel/core/gateway/stream_interceptor.py:61-67].
  - Tracks content in `sliding_window` of length 150 characters [VERIFIED sentinel/core/gateway/stream_interceptor.py:69-71].
  - Tracks full content in `ast_buffer` [VERIFIED sentinel/core/gateway/stream_interceptor.py:74].
  - **Circuit Breaker 1 (Canary Leak)**: If canary token is found in `sliding_window`, writes `log_security_event` to DB, yields `[RESPONSE TERMINATED DUE TO POLICY VIOLATION]`, yields `[DONE]`, and halts stream [VERIFIED sentinel/core/gateway/stream_interceptor.py:77-92].
  - **Circuit Breaker 2 (AST Taint Flow)**: When `ast_buffer` exceeds `ast_scan_threshold = 500` characters, runs `scan_response_text(ast_buffer)`. If dangerous Source→Sink flow is detected, writes `log_security_event` to DB, yields `[RESPONSE TERMINATED DUE TO POLICY VIOLATION]`, yields `[DONE]`, and halts stream [VERIFIED sentinel/core/gateway/stream_interceptor.py:94-111].
  - **Cleanup**: In `finally:`, ensures `await upstream_stream.aclose()` is executed [VERIFIED sentinel/core/gateway/stream_interceptor.py:126-128].

#### Path B: Non-Streaming (`stream=False`)
- Extracts full string from `upstream_response["choices"][0]["message"]["content"]` [VERIFIED sentinel/core/gateway/app.py:287-290].
- Calls `dlp_scanner.scan(content, canary_token, session_id, request_id)` to scrub canary tokens, PII (emails, SSNs), and API keys using regex replacements [VERIFIED sentinel/core/gateway/app.py:291; sentinel/core/gateway/dlp.py:15-53].
- Overwrites payload content with `redacted_content` [VERIFIED sentinel/core/gateway/app.py:295].
- Injects `security_metadata` object into response containing status (`VERIFIED_SAFE` or `FLAGGED_MONITORED`), decision, risk score, confidence, latency, and agent breakdown [VERIFIED sentinel/core/gateway/app.py:301-308].
- Dispatches audit write via `background_tasks.add_task(log_request, ...)` [VERIFIED sentinel/core/gateway/app.py:311-323].
- Returns finalized response dictionary [VERIFIED sentinel/core/gateway/app.py:325].

---

## 2. Concurrency, Worker & Threading Model

### Async Event Loop
- The gateway runs on `uvicorn` with an `asyncio` event loop [VERIFIED sentinel/requirements.txt:2; sentinel/run.py:74-84].
- Top-level route handlers (`chat_completions`, `inspect_prompt`, `inspect_tool_call`, `scan_code`, `scan_image`, `scan_document`) are declared as `async def` [VERIFIED sentinel/core/gateway/app.py:101, 328, 370, 463, 516, 586].

### Offloading Blocking Calls to ThreadPool
- CPU-intensive ML inferences and AST parsers are synchronous functions:
  - `judge.evaluate` [VERIFIED sentinel/core/detection/judge.py:97]
  - `vision_engine.scan_image` [VERIFIED sentinel/core/vision/engine.py:75]
  - `code_security_engine.scan_code` [VERIFIED sentinel/core/codesec/engine.py:35]
  - `malware_engine.scan_bytes` [VERIFIED sentinel/core/malware/engine.py:45]
- These functions are wrapped with `await asyncio.to_thread(...)`, which delegates execution to the default worker thread pool (`concurrent.futures.ThreadPoolExecutor`), preventing the main ASGI event loop from blocking [VERIFIED sentinel/core/gateway/app.py:154, 192, 439, 488, 549, 619].

### Background Task Queue
- Database audit logging (`log_request` and `log_security_event`) is decoupled from the HTTP response path using FastAPI's `BackgroundTasks.add_task` [VERIFIED sentinel/core/gateway/app.py:158, 234, 311].
- Logging is executed after the HTTP response has been committed to the network socket, removing SQLite disk commit latency from the user-facing request latency.

---

## 3. Connection Pooling, Timeouts, Retries & Backpressure

| Mechanism | Configuration / Value | Code Implementation |
| :--- | :--- | :--- |
| **HTTP Connection Pooling** | Persistent `httpx.AsyncClient(timeout=30.0)` created during startup lifespan | `sentinel/core/gateway/app.py:49` [VERIFIED] |
| **Ingress Decision SLA** | 10.0 seconds hard timeout (`asyncio.wait_for`) | `sentinel/core/gateway/app.py:193` [VERIFIED] |
| **Upstream Request Timeout** | 30.0 seconds socket read/connect timeout | `sentinel/core/gateway/app.py:49, 268` [VERIFIED] |
| **Database Busy Timeout** | 5000 ms (`PRAGMA busy_timeout=5000;`) | `sentinel/core/gateway/database.py:14` [VERIFIED] |
| **Upstream Retries** | **0 retries** (Fail-fast model; immediately raises HTTP 502 on exception) | `sentinel/core/gateway/app.py:273-276` [VERIFIED] |
| **Stream Backpressure** | Iterative SSE reading via `aiter_lines()`; client network backpressure propagates to upstream socket; `upstream_stream.aclose()` in `finally:` | `sentinel/core/gateway/stream_interceptor.py:52-128` [VERIFIED] |

---

## 4. Sequence Diagram

```
Client                 Sentinel Gateway                 Detection Engine           Upstream LLM
  │                           │                                │                        │
  │── POST /chat/completions ─►│                                │                        │
  │                           ├── session resolution           │                        │
  │                           ├── anti-SSRF image check        │                        │
  │                           │                                │                        │
  │                           │── asyncio.to_thread ──────────►│                        │
  │                           │   judge.evaluate() (<=10s)     ├── PatternHunter        │
  │                           │                                ├── SemanticAnalyst      │
  │                           │                                ├── BehavioralProfiler   │
  │                           │                                └── Stage2Arbiter        │
  │                           │◄─ verdict {ALLOW/BLOCK/FLAG} ──│                        │
  │                           │                                                         │
  │ [If BLOCK]                │                                                         │
  │◄── HTTP 403 Blocked ──────┤                                                         │
  │   (log in background)     ├── add_task(log_request)                                 │
  │                           │                                                         │
  │ [If ALLOW/FLAG]           │                                                         │
  │                           ├── inject_canary (honeytoken)                            │
  │                           │                                                         │
  │                           │── forward_to_upstream(stream=True) ────────────────────►│
  │                           │◄─ 200 OK SSE Stream ────────────────────────────────────│
  │                           │                                                         │
  │◄── 200 StreamingResponse ─┤                                                         │
  │                           │── stream_interceptor() ─────────────────────────────────┤
  │◄── data: chunk 1 ─────────┤   (yield line)                                          │
  │◄── data: chunk 2 ─────────┤   (yield line)                                          │
  │                           ├── sliding_window canary check                           │
  │                           ├── ast_buffer taint check (>500 chars)                   │
  │                           │                                                         │
  │ [If Violation Triggered]  │                                                         │
  │◄── data: [TERMINATED] ────┤   CIRCUIT BREAKER ACTIVATED                             │
  │◄── data: [DONE] ──────────┤   log_security_event()                                  │
  │                           ├── upstream_stream.aclose()                              │
```
