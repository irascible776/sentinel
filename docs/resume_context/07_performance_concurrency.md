# 07 Concurrency, Performance & Latency Engineering

This document provides a forensic audit of every latency-, throughput-, and concurrency-related mechanism in the Sentinel codebase.

---

## 1. Hot Path in Exact Execution Order

The critical hot path for user completions (`POST /v1/chat/completions`) executes the following sequential steps:

1. **High-Resolution Clock Start**: `t_start = time.perf_counter()` [VERIFIED sentinel/core/gateway/app.py:103].
2. **Payload Parsing**: `await request.json()`. Fails fast on malformed JSON with HTTP 400 [VERIFIED sentinel/core/gateway/app.py:105-107].
3. **Session ID Resolution**: Hierarchical resolution (payload $\to$ header `x-session-id` $\to$ cookie `sentinel_sid` $\to$ ephemeral UUID) [VERIFIED sentinel/core/gateway/app.py:110-115].
4. **Content Extraction & Anti-SSRF Gate**: Iterates over messages; extracts user strings; rejects remote HTTP/HTTPS image URLs immediately with HTTP 400 (`REMOTE_IMAGE_URL_UNSUPPORTED`) to eliminate SSRF and TOCTOU DNS rebinding [VERIFIED sentinel/core/gateway/app.py:120-149].
5. **Multimodal Inspection (if images present)**: Dispatches image bytes to `await asyncio.to_thread(vision_engine.scan_image, ...)` [VERIFIED sentinel/core/gateway/app.py:154]. If blocked, halts and returns HTTP 403 [VERIFIED sentinel/core/gateway/app.py:171].
6. **Ingress Multi-Agent Evaluation**: Dispatches `JudgeAgent.evaluate` to a worker thread with a strict 10.0-second timeout: `await asyncio.wait_for(asyncio.to_thread(judge.evaluate, prompt=user_text, session_id=session_id), timeout=10.0)` [VERIFIED sentinel/core/gateway/app.py:191-194].
   - **Step 6a**: `normalize_text(prompt)` (zero-width strip, NFKC, homoglyph skeletonization, slang expansion) [VERIFIED sentinel/core/detection/judge.py:81; sentinel/core/detection/normalizer.py:47-82].
   - **Step 6b**: `pattern_hunter.scan(inspected_prompt)` (mtime check, Base64 decoding, precompiled regex matching) [VERIFIED sentinel/core/detection/judge.py:84; sentinel/core/detection/pattern_hunter.py:88-158].
   - **Step 6c**: `semantic_analyst.analyze(inspected_prompt)` (string clamped to 2,000 chars, DeBERTa inference with `max_length=512`) [VERIFIED sentinel/core/detection/judge.py:89; sentinel/core/detection/semantic_analyst.py:102-145].
   - **Step 6d**: `intent_classifier.analyze(inspected_prompt)` (precompiled harm taxonomy keyword matching + action amplifier) [VERIFIED sentinel/core/detection/judge.py:94; sentinel/core/detection/intent_classifier.py:201-244].
   - **Step 6e**: `behavioral_profiler.evaluate_session(session_id, ...)` (under `_lock`: prunes records $>600\text{s}$, applies exponential decay $\tau=180\text{s}$, checks velocity) [VERIFIED sentinel/core/detection/judge.py:103; sentinel/core/detection/behavioral_profiler.py:59-172].
   - **Step 6f**: Gating Check: If `(not is_already_decided) and is_discrepancy_or_elevated`, invokes `stage2_arbiter.evaluate(prompt)` (GGUF Metal GPU or Groq HTTP POST) [VERIFIED sentinel/core/detection/judge.py:138-164].
   - **Step 6g**: Composite Risk Fusion & Corroboration Tiers [VERIFIED sentinel/core/detection/judge.py:169-235].
7. **Perimeter Enforcement Gate**:
   - If `verdict["decision"] == "BLOCK"`: dispatches asynchronous logging via `background_tasks.add_task(log_request, ...)`; returns HTTP 403 `JSONResponse` [VERIFIED sentinel/core/gateway/app.py:232-258].
8. **Honeytoken Instrumentation**: For clean prompts, calls `canary_engine.inject_into_prompt(messages, session_id)` to append `CANARY-SECRET-<uuid>` into system message [VERIFIED sentinel/core/gateway/app.py:261; sentinel/core/security_vectors/canary.py:21-48].
9. **Upstream Forwarding**: Uses persistent connection pool `app.state.http_client` to dispatch request to upstream LLM (Gemini / OpenAI / Ollama / Mock) [VERIFIED sentinel/core/gateway/app.py:265-272; sentinel/core/gateway/proxy.py:6-120].
10. **Egress Handling**:
    - **Streaming Path (`stream=True`)**: Wraps upstream stream in `stream_interceptor` generator; returns `StreamingResponse(..., media_type="text/event-stream")` [VERIFIED sentinel/core/gateway/app.py:280-283]. Interceptor evaluates sliding window (150 chars) for canary leaks and buffers code ($>500$ chars) for AST taint analysis; trips circuit breaker on violation [VERIFIED sentinel/core/gateway/stream_interceptor.py:68-111].
    - **Non-Streaming Path (`stream=False`)**: Extracts full response; executes `dlp_scanner.scan(content, ...)` for PII and canary scrub; attaches `security_metadata`; dispatches `background_tasks.add_task(log_request, ...)`; returns JSON [VERIFIED sentinel/core/gateway/app.py:287-325].

---

## 2. Inventory of Performance & Concurrency Mechanisms (FACTS)

### 1. In-Memory Caching
- **Tool Guardrail LRU Cache**: Implemented via `collections.OrderedDict` protected by `threading.Lock()` [VERIFIED sentinel/core/detection/tool_guardrail.py:34-37].
  - Key: SHA-256 digest of `f"{tool_name}:{canonical_json_args}"` [VERIFIED sentinel/core/detection/tool_guardrail.py:67].
  - Capacity: 1,024 items (`self._cache_max = 1024`) [VERIFIED sentinel/core/detection/tool_guardrail.py:36].
  - Eviction: Oldest entry evicted via `self._cache.popitem(last=False)` upon capacity breach [VERIFIED sentinel/core/detection/tool_guardrail.py:85].
  - TTL: None (pure deterministic argument hashing).
- **Code Security Scan Cache**: In-memory dictionary in `sentinel/core/codesec/engine.py:30, 48-55`. Key: SHA-256 of code string. Capacity: 1,024 entries (`MAX_CACHE_SIZE = 1024`) [VERIFIED sentinel/core/codesec/config.py:53].
- **OCR Driver Singleton Cache**: Factory caches driver instance in `OCRFactory._cached_engine` to avoid repeated capability probing [VERIFIED sentinel/core/vision/ocr/factory.py:22, 30-31].

### 2. Lazy Loading Strategies
- **DeBERTa Semantic Analyst**: Transformer pipeline is loaded lazily inside `_load_model()` [VERIFIED sentinel/core/detection/semantic_analyst.py:55-58]. Warmed up eagerly during FastAPI startup lifespan via `judge.evaluate("Warmup Sentinel gateway initialization", "sess-warmup")` [VERIFIED sentinel/core/gateway/app.py:52-56].
- **Stage 2 Arbiter GGUF**: `self._llm` lazy-loaded on first Stage 2 invocation; retained in memory across requests for process lifetime [VERIFIED sentinel/core/detection/stage2_arbiter.py:105, 205-219].
- **Redteam Strategist GGUF**: Gemma-2-2B-IT GGUF lazy-loaded on first redteam prompt mutation [VERIFIED sentinel/core/redteam/mutators/strategist.py:65-70].
- **Whisper Speech Recognizer**: Pipeline loaded on demand inside `get_transcriber()` [VERIFIED sentinel/core/security_vectors/voice_client.py:31-48].
- **Agentic Tool Guardrail Model**: Qwen2.5-Coder model lazy-loaded under mutex lock `self._load_lock` [VERIFIED sentinel/core/detection/tool_guardrail.py:33, 43].
- **MobileCLIP Feature Extractor**: Initialized on first visual concept scoring call [VERIFIED sentinel/core/vision/semantic/mobileclip_encoder.py:81-87].

### 3. Early Exits & Short-Circuiting
- **Anti-SSRF Image URL Rejection**: Rejects remote URLs immediately with HTTP 400 before invoking vision or text engines [VERIFIED sentinel/core/gateway/app.py:143-148].
- **Deterministic Prompt Injection Bypasses**: Stage 2 Arbiter is bypassed completely when fast signals already confirm high confidence: `p_score >= 95.0` or `(s_score >= 85.0 and p_score >= 40.0)` [VERIFIED sentinel/core/detection/judge.py:139].
- **Multimodal Early Exit**: If uploaded image is blocked by Pillar III, the request immediately terminates with HTTP 403 without invoking upstream LLM or Stage 2 text models [VERIFIED sentinel/core/gateway/app.py:155-181].
- **Text Presence Pre-OCR Filter**: Otsu binarization checks edge density; images with $<5\%$ edge density skip heavy OCR drivers entirely [VERIFIED sentinel/core/vision/preprocessing/text_presence.py:60-95].
- **Vision Deterministic Oracles**: Canary token hit in OCR text triggers immediate BLOCK without waiting for stego or noise pipelines [VERIFIED sentinel/core/vision/consensus/judge.py:47-60].
- **Code Security Tier 1 Short-Circuit**: Direct SQLi, RCE, or verified credentials trigger immediate BLOCK without waiting for CodeBERT neural inference [VERIFIED sentinel/core/codesec/judge.py:62-79].
- **Egress Circuit Breaker Trip**: `stream_interceptor` immediately halts upstream network streaming upon detecting canary leak or AST taint [VERIFIED sentinel/core/gateway/stream_interceptor.py:77-111].

### 4. Precompiled Regular Expressions & Fast Lookups
- Normalizer regexes compiled at module import: `_INVISIBLE_AND_BIDI_RE`, `_SLANG_AND_TYPOS`, `_REPEATED_CHARS_RE` [VERIFIED sentinel/core/detection/normalizer.py:5-45].
- Pattern Hunter compiled list: Rules in `threat_rules.json` are compiled once into `Tuple[Dict, re.Pattern]` on startup or file mtime change [VERIFIED sentinel/core/detection/pattern_hunter.py:37-45].
- Intent Classifier compiled taxonomy: Harm terms compiled into word-boundary regexes during initialization [VERIFIED sentinel/core/detection/intent_classifier.py:166-176].
- Master Judge tripwires compiled at module import: `_APP_PLANE_TRIPWIRE_RE`, `CTRL_TRIPWIRE_RE` [VERIFIED sentinel/core/detection/judge.py:28-36, 115-118].
- DLP scanner patterns compiled at initialization: `EMAIL`, `CREDIT_CARD`, `OPENAI_KEY`, `GEMINI_KEY`, `AWS_KEY` [VERIFIED sentinel/core/gateway/dlp.py:7-13].
- Secret scanner patterns compiled at module import: `AWS_KEY_PATTERN`, `GITHUB_PAT_PATTERN`, `PEM_KEY_PATTERN`, `JWT_PATTERN`, `SENSITIVE_ASSIGNMENT_PATTERN` [VERIFIED sentinel/core/codesec/secret_scanner.py:25-37].
- Egress AST analyzer sets: `DANGEROUS_SOURCES` (16 categories) and `DANGEROUS_SINKS` (13 categories) stored as Python `set` for $O(1)$ containment checks [VERIFIED sentinel/core/gateway/ast_analyzer.py:30-65].

### 5. Timeouts & SLA Budgets
- **Perimeter Ingress SLA**: Hard 10.0-second timeout enforced by `asyncio.wait_for(..., timeout=10.0)` [VERIFIED sentinel/core/gateway/app.py:193].
- **Upstream Connection Timeout**: 30.0 seconds on persistent HTTPX client [VERIFIED sentinel/core/gateway/app.py:49, 268].
- **Stage 2 HTTP Phased Timeout**: Phased timeout with 1.0s connect, 1.0s write, 1.0s pool, and 3.0s total read timeout [VERIFIED sentinel/core/detection/stage2_arbiter.py:168].
- **Malware Scan Timeout**: 8.0 seconds hard ceiling (`SCAN_TIMEOUT_SECONDS = 8.0`) [VERIFIED sentinel/core/malware/config.py:38].
- **SQLite Database Busy Timeout**: 5000 ms (`PRAGMA busy_timeout=5000;`) [VERIFIED sentinel/core/gateway/database.py:14].

### 6. Concurrency, Threading & Connection Pools
- **Asynchronous Offloading**: CPU-bound inferences (`judge.evaluate`, `vision_engine.scan_image`, `code_security_engine.scan_code`, `malware_engine.scan_bytes`) are delegated to worker threads via `await asyncio.to_thread(...)`, keeping the ASGI event loop free for concurrent I/O [VERIFIED sentinel/core/gateway/app.py:154, 192, 439, 488, 549, 619].
- **Persistent HTTP Connection Pools**:
  - Ingress Gateway: Shared `app.state.http_client = httpx.AsyncClient(timeout=30.0)` created during startup lifespan [VERIFIED sentinel/core/gateway/app.py:49, 265].
  - Stage 2 Arbiter: Persistent `httpx.Client` with `limits = httpx.Limits(max_keepalive_connections=20, max_connections=50, keepalive_expiry=30.0)` [VERIFIED sentinel/core/detection/stage2_arbiter.py:167-174].
- **Locks & Synchronization**:
  - `BehavioralProfiler._lock`: `threading.Lock()` synchronizing session memory access and pruning [VERIFIED sentinel/core/detection/behavioral_profiler.py:23, 75].
  - `AgenticToolGuardrail._load_lock` and `_cache_lock`: `threading.Lock()` instances [VERIFIED sentinel/core/detection/tool_guardrail.py:33-34].
- **SQLite WAL Mode**: `PRAGMA journal_mode=WAL;` enables non-blocking concurrent readers while background tasks commit audit writes [VERIFIED sentinel/core/gateway/database.py:13].
- **Background Audit Logging**: `BackgroundTasks.add_task(log_request, ...)` decouples SQLite disk commits from user-facing HTTP response latency [VERIFIED sentinel/core/gateway/app.py:158, 234, 311].

### 7. Size Caps & Memory Budgets
- Prompt length clamped to first 2,000 characters before DeBERTa tokenization [VERIFIED sentinel/core/detection/semantic_analyst.py:121].
- Behavioral profiler session memory capped at 10,000 sessions with automated 20% oldest eviction [VERIFIED sentinel/core/detection/behavioral_profiler.py:22, 50-57].
- Malware upload ceiling: 32 MB hard ceiling (`MAX_FILE_BYTES = 32 * 1024 * 1024`) with 64 KB spooling buffer [VERIFIED sentinel/core/malware/config.py:9-10].
- MalConv sequence bound: 2 MB (`MALCONV_MAX_SEQ_LEN = 2097152`) [VERIFIED sentinel/core/malware/config.py:13].
- Code scanning limits: 1 MB max size, 5,000 lines max, AST recursion depth 100 [VERIFIED sentinel/core/codesec/config.py:50-52].
- Vision max image dimension: 2048px maximum dimension [VERIFIED sentinel/core/vision/preprocessing/image_prep.py:50-65].

---

## 3. Potential Bottlenecks & Hypotheses (HYPOTHESES)

> [!NOTE]
> The following items are architectural inferences and potential bottlenecks identified through structural code analysis. Each item is marked `[UNVERIFIED]` as it represents a theoretical performance risk rather than a stored benchmark measurement.

1. **GIL Contention during Concurrent CPU Inferences** [UNVERIFIED]:
   Because `asyncio.to_thread` runs synchronous functions inside Python's default `ThreadPoolExecutor`, concurrent CPU-bound tasks (PyTorch DeBERTa inference, AST parsing, and regex passes) execute under the CPython Global Interpreter Lock (GIL). Under high concurrency, worker threads may contend for the GIL, degrading overall event-loop throughput on multi-core servers.
2. **SQLite WAL Write Lock Contention at Scale** [UNVERIFIED]:
   While SQLite WAL mode allows concurrent readers, write operations remain serialized. In high-throughput production environments (e.g., hundreds of requests per second), concurrent `BackgroundTasks` executing `log_request` could serialize at the SQLite database lock, potentially exhausting the 5,000ms busy timeout.
3. **AST Re-parsing Overhead on Streaming Code Outputs** [UNVERIFIED]:
   In `sentinel/core/gateway/stream_interceptor.py:95`, `check_ast_taint(ast_buffer)` runs `scan_response_text(full_text)` whenever `len(full_text) >= 500`. On every incoming SSE token chunk after 500 characters, Python's `ast.parse` re-parses the entire accumulated code buffer from scratch. For large code completions (e.g., thousands of lines), repeated AST parsing could introduce per-chunk egress latency.
4. **Base64 Regex Parsing on Large Text Inputs** [UNVERIFIED]:
   In `sentinel/core/detection/pattern_hunter.py:66`, the regular expression `[A-Za-z0-9+/]{16,}={0,2}` executes over the input text prior to length clamping. An adversary submitting a multi-megabyte benign prompt with high character entropy could force excessive regex backtracking and memory allocation before truncation occurs.
5. **Periodic Session Pruning Lock Hold Time** [UNVERIFIED]:
   In `sentinel/core/detection/behavioral_profiler.py:35-58`, `_periodic_global_cleanup` iterates over all sessions in `self.sessions` every 5 minutes while holding `self._lock`. If the session dictionary reaches its 10,000-session cap, sorting and evicting 2,000 sessions under the lock could briefly delay ingress request processing for concurrent connections.
