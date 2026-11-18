# 12 CV Claim Forensic Audit

This document audits the 8 specific technical claims evaluated for candidate resumes for Sentinel. Every claim is assigned a strict verdict (`VERIFIED`, `PARTIALLY VERIFIED`, `CONTRADICTED`, or `NOT FOUND`) with code and stored result citations.

---

## 1. Summary Scorecard

| # | Resume Claim | Forensic Verdict | Evidence Citation | Measurement Stored vs Fresh |
| :--- | :--- | :--- | :--- | :--- |
| **a** | Multi-agent gateway combining regex pattern matching, DeBERTa-v3 classification and behavioral profiling | **VERIFIED** | `sentinel/core/detection/judge.py:46-51, 80-244` | Fully implemented in code |
| **b** | "96.4% precision and 1.0% false-positive rate across 662 public prompt-injection samples" | **VERIFIED [STORED RESULT]** | `sentinel/tests/samples/benchmark_report_deepset_all_662.json:1-17` | **Stored measurement found in repo** |
| **c** | Reverse proxy that intercepts streaming LLM responses via SSE and aborts mid-stream on policy violations | **VERIFIED** | `sentinel/core/gateway/app.py:278-283; sentinel/core/gateway/stream_interceptor.py:6-128` | Fully implemented in code |
| **d** | Canary-token honeypots detecting system-prompt leaks "in under 0.01ms" | **PARTIALLY VERIFIED** | `sentinel/core/security_vectors/canary.py:15-54; sentinel/core/gateway/stream_interceptor.py:76-92` | Mechanism verified; **number needs fresh run** |
| **e** | RAG poisoning scanner with overlapping chunking | **VERIFIED** | `sentinel/core/security_vectors/rag_scanner.py:42-98` | Fully implemented in code |
| **f** | TF-IDF threat-intelligence pipeline auto-synthesizing attack signatures "in under 150ms" | **PARTIALLY VERIFIED** | `sentinel/core/security_vectors/threat_feed.py:22-185` | Mechanism verified; **number needs fresh run** |
| **g** | Chrome Extension | **VERIFIED** | `sentinel/extension/manifest.json:1-34; sentinel/extension/content.js:1-151` | Fully implemented in code |
| **h** | Whisper-based voice client | **VERIFIED** | `sentinel/core/security_vectors/voice_client.py:1-152` | Fully implemented in code |

---

## 2. Detailed Forensic Audit per Claim

### Claim (a): Multi-Agent Gateway Combining Regex, DeBERTa-v3, and Behavioral Profiling
- **Verdict**: **VERIFIED**
- **Evidence**:
  - `Master Judge Agent`: `sentinel/core/detection/judge.py:46-51` initializes `PatternHunter`, `SemanticAnalyst`, `IntentClassifier`, and `BehavioralProfiler` [VERIFIED].
  - `Pattern Hunter`: `sentinel/core/detection/pattern_hunter.py:14-158` compiles and scans regex signatures from `threat_rules.json` and decodes Base64 payloads [VERIFIED].
  - `Semantic Analyst`: `sentinel/core/detection/semantic_analyst.py:12-152` runs Hugging Face DeBERTa-v3 classification with 512-token truncation [VERIFIED].
  - `Behavioral Profiler`: `sentinel/core/detection/behavioral_profiler.py:14-172` manages in-memory multi-turn session risk with exponential decay $\tau=180\text{ s}$ and velocity tracking [VERIFIED].
  - `Weighted Fusion`: `sentinel/core/detection/judge.py:169-176` computes composite risk via $0.20 \times \text{Pattern} + 0.35 \times \text{Semantic} + 0.30 \times \text{Intent} + 0.15 \times \text{Behavioral}$ [VERIFIED].

---

### Claim (b): "96.4% precision and 1.0% false-positive rate across 662 public prompt-injection samples."
- **Verdict**: **VERIFIED [STORED RESULT]**
- **Evidence**:
  - Benchmark Report: `sentinel/tests/samples/benchmark_report_deepset_all_662.json:1-17` [STORED RESULT].
  - Raw JSON metrics in repository:
    ```json
    {
      "dataset": "deepset/prompt-injections (full)",
      "total_samples": 662,
      "attacks_count": 263,
      "benign_count": 399,
      "accuracy_pct": 75.83,
      "precision_pct": 96.4,
      "recall_pct": 40.68,
      "f1_score": 0.5722,
      "false_positive_rate_pct": 1.0,
      "avg_latency_ms": 678.02,
      "execution_time_sec": 448.87,
      "tp": 107,
      "tn": 395,
      "fp": 4,
      "fn": 156
    }
    ```
  - Dataset File: `sentinel/tests/samples/benchmark_deepset_all_662.json` contains exactly 662 samples (263 attacks, 399 benign) [VERIFIED command output].
  - Evaluation Script: `sentinel/tests/benchmark_full_662.py:1-175` [VERIFIED].
- **Measurement Status**: **STORED RESULT FOUND**. The numbers `96.4%` precision and `1.0%` false-positive rate are recorded verbatim in `benchmark_report_deepset_all_662.json`. They do NOT need to be measured fresh to be cited as historical evaluation results.
- **Contextual Note for Interviews**: While precision is 96.4% and FPR is 1.0%, candidate should note that recall was 40.68% (107/263 attacks caught) and overall accuracy was 75.83%, because the gateway was calibrated conservatively to prevent false alarms on benign queries.

---

### Claim (c): Reverse Proxy Intercepting Streaming LLM Responses via SSE and Aborting Mid-Stream on Policy Violations
- **Verdict**: **VERIFIED**
- **Evidence**:
  - Reverse Proxy Forwarding: `sentinel/core/gateway/proxy.py:6-120` supports streaming via `client.send(req, stream=True)` [VERIFIED].
  - Streaming Route: `sentinel/core/gateway/app.py:278-283` returns `StreamingResponse(stream_interceptor(...), media_type="text/event-stream")` [VERIFIED].
  - Mid-Stream Circuit Breaker: `sentinel/core/gateway/stream_interceptor.py:6-128`:
    - Evaluates incoming SSE chunks via `aiter_lines()`.
    - Tracks canary token in 150-char sliding window; tracks generated code in AST accumulation buffer.
    - If canary leak detected: yields `data: {"choices": [{"delta": {"content": "\n\n[RESPONSE TERMINATED DUE TO POLICY VIOLATION]"}}]}\n\n`, yields `data: [DONE]\n\n`, and halts execution [VERIFIED sentinel/core/gateway/stream_interceptor.py:76-92].
    - If AST taint flow detected ($>500$ chars): halts stream with identical termination chunk [VERIFIED sentinel/core/gateway/stream_interceptor.py:94-111].
    - Socket Cleanup: `finally:` block executes `await upstream_stream.aclose()` [VERIFIED sentinel/core/gateway/stream_interceptor.py:126-128].

---

### Claim (d): Canary-Token Honeypots Detecting System-Prompt Leaks "in under 0.01ms."
- **Verdict**: **PARTIALLY VERIFIED**
- **Evidence**:
  - Mechanism Implemented: `CanaryEngine` in `sentinel/core/security_vectors/canary.py:10-54` generates tokens with prefix `CANARY-SECRET-` and injects them into system messages.
  - Substring Matching: Detection uses Python's in-memory exact substring check: `canary_token in text` [VERIFIED sentinel/core/security_vectors/canary.py:54].
  - Stream Monitoring: Checked per SSE delta chunk within a 150-character sliding window [VERIFIED sentinel/core/gateway/stream_interceptor.py:21, 77].
- **Measurement Status**: **NO STORED MEASUREMENT FILE**. While Python C-level substring search on a 150-char buffer takes less than 10 microseconds (<0.01ms), the repository does not contain a saved timing file recording the "under 0.01ms" figure. To state "under 0.01ms" with experimental backing, **a fresh micro-benchmark must be executed**.

---

### Claim (e): RAG Poisoning Scanner with Overlapping Chunking
- **Verdict**: **VERIFIED**
- **Evidence**:
  - Class: `sentinel/core/security_vectors/rag_scanner.py:RAGScanner` [VERIFIED sentinel/core/security_vectors/rag_scanner.py:42-138].
  - Overlapping Chunking: `chunk_text(text, chunk_size=500, overlap=50)` slices text with step size `max(1, chunk_size - overlap) = 450` [VERIFIED sentinel/core/security_vectors/rag_scanner.py:51-75].
  - In-Process Multi-Agent Evaluation: Calls `self.judge.evaluate(chunk, session_id="rag-scanner-system")` directly in-process [VERIFIED sentinel/core/security_vectors/rag_scanner.py:85-86].
  - Quarantine Logic: If `risk_score >= 75.0` or `decision == "BLOCK"`, quarantines chunk and marks document as poisoned (`is_poisoned = True`) [VERIFIED sentinel/core/security_vectors/rag_scanner.py:88-97].

---

### Claim (f): TF-IDF Threat-Intelligence Pipeline Auto-Synthesizing Attack Signatures "in under 150ms."
- **Verdict**: **PARTIALLY VERIFIED**
- **Evidence**:
  - Class: `sentinel/core/security_vectors/threat_feed.py:ThreatIntelligenceFeed` [VERIFIED sentinel/core/security_vectors/threat_feed.py:22-185].
  - SQLite WAL Extraction: Queries `requests` table where `decision = 'BLOCK'` [VERIFIED sentinel/core/security_vectors/threat_feed.py:43-48].
  - N-Gram Clustering: Uses Scikit-Learn `TfidfVectorizer(ngram_range=(2, 4), min_df=2, stop_words="english")` [VERIFIED sentinel/core/security_vectors/threat_feed.py:59-64].
  - Signature Synthesis: Converts top n-grams into regex patterns with wildcard tokens (`\bword1\s+(?:\w+\s+)*?word2\b`) and writes them directly to `threat_rules.json` [VERIFIED sentinel/core/security_vectors/threat_feed.py:90-175].
  - Live Ingestion: `PatternHunter.load_rules()` hot-reloads modified rules locklessly on the next incoming request [VERIFIED sentinel/core/detection/pattern_hunter.py:31-53].
- **Measurement Status**: **NO STORED MEASUREMENT FILE**. While running TF-IDF on 100 short text strings executes in under 50ms on modern CPUs, there is no JSON benchmark report or log in the repository containing the "under 150ms" measurement. To claim "under 150ms" with proof, **a fresh benchmark must be run**.

---

### Claim (g): Chrome Extension
- **Verdict**: **VERIFIED**
- **Evidence**:
  - Directory: `sentinel/extension/` [VERIFIED sentinel/extension/manifest.json:1-34].
  - Specification: Manifest V3 extension targeting `chatgpt.com`, `claude.ai`, and localhost [VERIFIED sentinel/extension/manifest.json:1-29].
  - DOM Interception: `sentinel/extension/content.js:1-151` intercepts textarea input events, dispatches the prompt to `http://127.0.0.1:8000/api/v1/inspect`, and displays an overlay banner warning or blocking the submission if malicious [VERIFIED sentinel/extension/content.js:20-145].
  - Popup GUI: `sentinel/extension/popup.html:1-116` and `popup.js:1-37` manage gateway URL configuration and active interception toggles [VERIFIED].

---

### Claim (h): Whisper-Based Voice Client
- **Verdict**: **VERIFIED**
- **Evidence**:
  - File: `sentinel/core/security_vectors/voice_client.py:1-152` [VERIFIED].
  - Audio Hardware Integration: Captures live microphone audio using `sounddevice` at 16,000 Hz or reads WAV files via `soundfile` [VERIFIED sentinel/core/security_vectors/voice_client.py:24, 75-120].
  - Speech Recognition: Hugging Face `pipeline("automatic-speech-recognition", model="openai/whisper-tiny", device="cpu")` [VERIFIED sentinel/core/security_vectors/voice_client.py:37-43].
  - Gateway Bridge: Posts transcribed prompt to `http://127.0.0.1:8000/v1/chat/completions` to test gateway ingress defenses against spoken attacks [VERIFIED sentinel/core/security_vectors/voice_client.py:125-148].
