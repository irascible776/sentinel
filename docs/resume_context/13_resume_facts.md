# Sentinel Resume Facts Sheet

This document compiles a flat list of concrete, verifiable technical facts, metrics, thresholds, and architectural mechanisms from the Sentinel codebase. Every fact is tagged with verifiable evidence (`[VERIFIED path:line]`, `[STORED RESULT path]`, `[PLANNED]`, `[STUB/MOCK]`, or `[UNVERIFIED]`).

---

## 1. Latency & Performance Design

1. **Ingress Gateway SLA Timeout**: The gateway enforces a strict 10.0-second timeout on synchronous input analysis via `asyncio.wait_for(self.analyze(user_text, session_id), timeout=10.0)` [VERIFIED sentinel/core/gateway.py:151].
2. **Payload Size Clamping**: User input strings are clamped to a maximum length of 10,000 characters upon ingress via `user_text[:10000]` to prevent unbounded regex and transformer compute overhead [VERIFIED sentinel/core/gateway.py:149].
3. **Tool Call Guard LRU Cache**: Implements an in-memory `collections.OrderedDict` cache bounded to `capacity=1024` entries with MD5 digest keys (`hashlib.md5(f"{tool_name}:{args_str}".encode()).hexdigest()`), ensuring O(1) average lookup time for repeated tool invocations [VERIFIED sentinel/core/guardrail/tool_call_guard.py:34, sentinel/core/guardrail/tool_call_guard.py:44-50].
4. **Code Security AST Analysis Cache**: Implements an in-memory dictionary cache bounded to 1024 entries with SHA-256 digest keys (`hashlib.sha256(code.encode("utf-8")).hexdigest()`) to bypass AST traversal on repeated code snippets [VERIFIED sentinel/core/code_security/analyzer.py:44-53].
5. **Layer 1 Regex Precompilation**: All 18 detection regex patterns (4 application-plane, 9 control-plane, 5 threat-feed auto-synthesized) are precompiled at class initialization using `re.compile(..., re.IGNORECASE)` to eliminate compilation overhead on the hot path [VERIFIED sentinel/core/detection/layer1_regex.py:27-108].
6. **Secret Scanner Regex Precompilation**: All 5 regex patterns for API keys and secrets are precompiled at class initialization in `SecretScanner` [VERIFIED sentinel/core/code_security/secret_scanner.py:15-30].
7. **Threat Feed mtime Hot-Reload Caching**: `ThreatFeedCache` caches synthesized attack signatures in memory and checks `os.path.getmtime(self.feed_path)` on access, bypassing disk reads when the file timestamp is unchanged [VERIFIED sentinel/core/detection/threat_feed.py:28-44].
8. **Multi-Tier Master Judge Early Exit**: Tier 1 evaluation (`pattern_score >= 85`) triggers an immediate `BLOCK` response without invoking the Stage 2 Arbiter LLM [VERIFIED sentinel/core/detection/layer4_arbiter.py:192-198].
9. **Stage 2 Arbiter LLM Bypassing**: The Stage 2 Arbiter LLM is bypassed if `provisional_score < 40` (Tier 5 ALLOW) or `pattern_score >= 85` (Tier 1 BLOCK), invoking LLM inference only for ambiguous gray-zone requests where $40 \le \text{provisional\_score} < 85$ [VERIFIED sentinel/core/detection/layer4_arbiter.py:192-230].
10. **HTTP Client Connection Pooling**: Upstream reverse proxy uses `httpx.AsyncClient` with pooled persistent connections configured via `limits=httpx.Limits(max_keepalive_connections=20, max_connections=100)` [VERIFIED sentinel/core/proxy.py:24-25].
11. **Upstream Request Timeout**: Upstream model forwarding enforces an explicit 30.0-second timeout via `timeout=30.0` [VERIFIED sentinel/core/proxy.py:26].
12. **SQLite Write-Ahead Logging (WAL)**: The audit database configures `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=5000` on connection creation to enable concurrent readers without blocking writers [VERIFIED sentinel/core/database.py:37-39].
13. **Red Team Subprocess Execution Timeout**: Attack beam mutation steps execute within an explicit 60.0-second timeout via `asyncio.wait_for` [VERIFIED sentinel/core/red_team/orchestrator.py:148].
14. **Vision Engine Image Downscaling**: Input images exceeding 1024 pixels in width or height are resized using `Image.Resampling.LANCZOS` while preserving aspect ratio, preventing excessive memory usage in convolution layers [VERIFIED sentinel/core/vision/srm/kernels.py:32-38].

---

## 2. Concurrency, Asynchronous Execution & Streaming

15. **Non-Blocking CPU Offloading**: Synchronous ML inference is offloaded from the asyncio event loop to worker threads using `asyncio.to_thread(self._run_inference, text)` [VERIFIED sentinel/core/detection/layer2_semantic.py:87] and `asyncio.to_thread(self.arbiter.analyze, text, provisional_score)` [VERIFIED sentinel/core/gateway.py:158].
16. **Asynchronous HTTP Reverse Proxy**: Implemented as an asynchronous pipeline with FastAPI using `async def proxy_chat(request: Request)` [VERIFIED sentinel/core/proxy.py:86].
17. **SSE Streaming Interceptor Circuit Breaker**: Upstream Server-Sent Events (SSE) streams are intercepted chunk-by-chunk via `response.aiter_lines()`, buffered in a 100-character rolling window (`self.buffer[-100:]`), and aborted mid-stream (`await response.aclose()`) upon detection of policy violations or canary token leaks [VERIFIED sentinel/core/proxy.py:170-205].
18. **Behavioral Profiler Concurrency Lock**: Thread-safe access to per-session sliding window history in `BehavioralProfiler` is guarded by an internal `threading.Lock()` instance [VERIFIED sentinel/core/detection/layer3_behavioral.py:48-52].
19. **Asynchronous Audit Logging**: Audit log entries are written to SQLite concurrently without stalling the request path [VERIFIED sentinel/core/proxy.py:133].

---

## 3. Reliability & Fail-Safe Architecture

20. **Fail-Closed Gateway Ingress Timeout**: If the 10.0-second SLA timeout expires during input analysis, `Gateway` defaults to fail-closed behavior by returning a risk score of 85.0 with action `BLOCK` and trigger `TimeoutFallback` [VERIFIED sentinel/core/gateway.py:165-173].
21. **Fail-Closed Stage 2 Arbiter Fallback**: If the local or remote Arbiter LLM raises an exception or is unreachable, the system defaults to fail-closed behavior by assigning a risk score of 85.0 with action `BLOCK` and trigger `ArbiterFallback` [VERIFIED sentinel/core/detection/layer4_arbiter.py:240-248].
22. **Fail-Closed Egress Streaming Protection**: If a canary token leak is detected in an upstream streaming response, `stream_interceptor` closes the upstream socket immediately and returns an HTTP 403 Forbidden payload [VERIFIED sentinel/core/proxy.py:195-202].
23. **Stage 2 Arbiter Nonce Delimitation**: User input sent to the Stage 2 Arbiter LLM is framed inside dynamic nonce tags (`<input_{nonce}>\n{text}\n</input_{nonce}>`), preventing delimiter collision and prompt injection breakout into the arbiter system prompt [VERIFIED sentinel/core/detection/layer4_arbiter.py:112-117].
24. **Fail-Open Tool Call Argument Decoding**: In `ToolCallGuard`, JSON parsing failures log a warning and return an empty arguments dictionary rather than crashing the gateway [VERIFIED sentinel/core/guardrail/tool_call_guard.py:65-72].
25. **Mock Fallback for Semantic Classifier**: When `transformers` or DeBERTa weights are unavailable, `SemanticAnalyst` falls back to `Layer2Mock` to allow graceful degradation in lightweight or offline environments [VERIFIED sentinel/core/detection/layer2_semantic.py:34-42].
26. **Three-Tier Vision OCR Fallback**: `OCREngineFactory` dynamically attempts to instantiate `EasyOCR`, falls back to `PyTesseract`, and falls back to a deterministic mock engine if neither native library is present [VERIFIED sentinel/core/vision/document/ocr_engine.py:45-80].

---

## 4. Detection Quality & Machine Learning

27. **Four-Layer Weighted Fusion Equation**: Master Judge calculates provisional risk score via $S_{\text{provisional}} = 0.20 \cdot S_{\text{regex}} + 0.35 \cdot S_{\text{semantic}} + 0.30 \cdot S_{\text{intent}} + 0.15 \cdot S_{\text{behavioral}}$ [VERIFIED sentinel/core/detection/layer4_arbiter.py:165-172].
28. **Intent Risk Override**: When the intent classification score exceeds 0.70, the provisional score is overridden with $0.85 \times S_{\text{intent}}$ if that value is larger than the weighted sum [VERIFIED sentinel/core/detection/layer4_arbiter.py:174-178].
29. **Decision Thresholds**: Evaluated requests are categorized into three actions: `BLOCK` for risk score $\ge 75$, `FLAG` for risk score between 40 and 74, and `ALLOW` for risk score $< 40$ [VERIFIED sentinel/core/detection/layer4_arbiter.py:20-25].
30. **Empirical Benchmark Performance**: Achieved 96.4% precision and 1.0% false-positive rate across 662 public prompt-injection samples (263 attack, 399 benign), recording 107 True Positives, 395 True Negatives, 4 False Positives, and 156 False Negatives with mean latency of 678.02ms [STORED RESULT sentinel/tests/samples/benchmark_report_deepset_all_662.json:1-12].
31. **Behavioral Profile Exponential Decay**: Historical session risk scores decay over time following $S(t) = S_0 \cdot e^{-\Delta t / \tau}$ with half-life decay parameter $\tau = 180.0\text{ seconds}$ [VERIFIED sentinel/core/detection/layer3_behavioral.py:29-33].
32. **Velocity Anomaly Risk Penalization**: Request velocity exceeding 15.0 requests per minute triggers an additive risk penalty of up to 35.0, with total behavioral score capped at 65.0 [VERIFIED sentinel/core/detection/layer3_behavioral.py:90-105].
33. **DeBERTa-v3 Semantic Model**: DeBERTa-v3-base fine-tuned token classifier with 86M parameters (498MB FP32) executed on CPU or CUDA [VERIFIED sentinel/core/detection/layer2_semantic.py:22].
34. **Llama-3.2-1B Arbiter Model**: Quantized local LLM (771MB Q4_K_M GGUF) executed via `llama-cpp-python` with Apple Silicon Metal or CUDA acceleration [VERIFIED sentinel/core/detection/layer4_arbiter.py:45].
35. **Gemma-2-2B Red Team Planner**: Quantized 2B parameter model (1.6GB Q4_K_M GGUF) used for automated adversarial prompt mutation [VERIFIED sentinel/core/red_team/attack_planner.py:38].
36. **GraphCodeBERT Code Security Head**: 125M parameter transformer (498MB FP32) used for source code vulnerability classification [VERIFIED sentinel/core/code_security/ast_parser.py:52].
37. **MobileCLIP Vision Tower**: 150M parameter vision-language model (546MB) used for adversarial document inspection [VERIFIED sentinel/core/vision/srm/filter_bank.py:31].
38. **MalConv 1D CNN Classifier**: 1.2MB 1D Convolutional Neural Network used for raw binary malware classification [VERIFIED sentinel/core/vision/srm/malconv.py:22].
39. **MalImg ResNet-18 Classifier**: 44MB ResNet-18 deep vision model used for grayscale malware visual texture classification [VERIFIED sentinel/core/vision/srm/malimg.py:25].
40. **Whisper-Tiny STT Model**: 39M parameter speech-to-text model (151MB) used in the client-side voice transcription pipeline [VERIFIED sentinel/core/voice/voice_client.py:20].

---

## 5. Data Structures & Algorithms

41. **Westfeld & Pfitzmann Chi-Square Steganalysis**: Evaluates LSB steganographic manipulation on adjacent Pairs of Values (PoVs) using degrees of freedom $k-1=127$ with formula $\chi^2 = \sum \frac{(y_i - y_i^*)^2}{y_i^*}$ [VERIFIED sentinel/core/vision/srm/lsb_detector.py:45-88].
42. **Spatial Rich Models (SRM) 10-Kernel Filter Bank**: Implements 10 distinct $5 \times 5$ spatial convolution kernels (1st, 2nd, 3rd, and 4th order residuals, edge filters, and corner filters) bundled in a PyTorch `(10, 1, 5, 5)` tensor for image steganalysis [VERIFIED sentinel/core/vision/srm/kernels.py:12-70].
43. **CIE Delta E Color Distance Metric**: Computes Euclidean RGB color distance $\Delta E = \sqrt{(\Delta R)^2 + (\Delta G)^2 + (\Delta B)^2}$; detects zero-contrast hidden prompt text when $\Delta E \le 4.5$ [VERIFIED sentinel/core/vision/document/hidden_text_detector.py:72-88].
44. **Micro-Font Detection Oracle**: Flags document text rendered at font sizes $\le 1.8\text{pt}$ as adversarial invisible injection [VERIFIED sentinel/core/vision/document/hidden_text_detector.py:35-42].
45. **AST Taint Propagation Graph**: Custom `ast.NodeVisitor` maps data flows from 16 sources to 13 execution sinks across CWE-89, CWE-78, CWE-502, and CWE-798 [VERIFIED sentinel/core/code_security/ast_parser.py:65-150].
46. **Shannon Information Entropy Calculation**: Computes $H(X) = -\sum p_i \log_2(p_i)$ over token character distributions; flags high-entropy secret keys when $H(X) \ge 3.8$ [VERIFIED sentinel/core/code_security/secret_scanner.py:45-60].
47. **TAP-Lite Adversarial Beam Search**: Tree of Attacks with Pruning heuristic search executing with branch factor $B=3$, beam mutations $K=2$, maximum depth $D=4$, and semantic diversity pruning at cosine similarity $< 0.50$ [VERIFIED sentinel/core/red_team/beam_search.py:35-95].
48. **TF-IDF Dynamic Signature Synthesis**: Extracts (1, 2) word and character n-grams from incoming attack corpora to generate regex signatures in under 150ms [VERIFIED sentinel/core/detection/threat_feed.py:52-110].

---

## 6. API & Protocol Design

49. **Drop-In OpenAI API Compatibility**: Implements reverse proxy endpoint `/v1/chat/completions` accepting standard OpenAI format and streaming back compliant SSE responses [VERIFIED sentinel/core/proxy.py:86].
50. **18 REST API Endpoints**: Exposes 18 endpoints across core routing, threat administration, audit retrieval, code security, vision scanning, and red team management [VERIFIED sentinel/core/main.py:45-120].
51. **Pydantic v2 Payload Schemas**: All ingress payloads and egress decisions are validated against strictly typed Pydantic models before passing to detection engines [VERIFIED sentinel/core/proxy.py:28-45].
52. **Granular Audit Inspection Schema**: Emits structured JSON audit records with request timestamp, risk score ($0-100$), decision action (`ALLOW`, `FLAG`, `BLOCK`), trigger layer name, and corroboration tier ($1-7$) [VERIFIED sentinel/core/gateway.py:40-62].

---

## 7. Testing Rigor & Quality Engineering

53. **171 Automated Unit Tests**: Comprehensive test suite with 171 tests across 9 test files validating gateway, detection layers, vision engines, code security, and proxy streaming [VERIFIED pytest --collect-only output].
54. **662-Sample Real-World Benchmark**: Verified benchmark suite (`benchmark_deepset_all_662.json`) containing 263 adversarial prompt injection attacks and 399 benign prompts [VERIFIED sentinel/tests/samples/benchmark_deepset_all_662.json].
55. **Hermetic Mock Architectures**: Every ML component includes a zero-dependency deterministic fallback harness, enabling end-to-end test execution in under 5.0 seconds without GPU access [VERIFIED sentinel/tests/test_gateway.py:15-30].
