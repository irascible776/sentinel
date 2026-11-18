# 09 Tests & Benchmarks Inventory

This document details all test suites, benchmark scripts, evaluation datasets, and stored historical performance reports in the Sentinel repository.

---

## 1. Test Suite Coverage & Execution Commands

Command used to collect tests:
`cd sentinel && python3 -m pytest --collect-only -q`
Total collected unit and integration tests: **171 tests** [VERIFIED command output].

| Test File | Test Count | Scope & Coverage | Execution Command |
| :--- | :--- | :--- | :--- |
| `sentinel/tests/test_code_security.py` | 30 | Pillar II: Shannon entropy bounds, AWS/JWT/PEM structural secret detection, false-positive placeholder rejection, Python AST SQLi, OS command injection, pickle deserialization, `# nosec` line suppression, multi-language regex lexer, GraphCodeBERT DFG tokenization and inference, 3-tier precedence judge, cache behavior, API `/api/v1/scan-code` [VERIFIED sentinel/tests/test_code_security.py:1-521] | `pytest tests/test_code_security.py` |
| `sentinel/tests/test_components.py` | 2 | Response-side DLP PII/secret redaction (`test_dlp_scanner`) and streaming circuit breaker termination on canary leak (`test_stream_interceptor_circuit_breaker`) [VERIFIED sentinel/tests/test_components.py:1-28] | `pytest tests/test_components.py` |
| `sentinel/tests/test_detection.py` | 25 | Ingress Detection: PatternHunter clean prompts, instruction overrides, DAN persona, Base64 decoding; SemanticAnalyst benign and roleplay prompts, 512-token truncation; BehavioralProfiler single-turn, multi-turn escalation, session isolation; Master Judge ALLOW/BLOCK/FLAG contracts; Stage2Arbiter missing key fallback, mock attack detection, Gemini safety finish reason, timeout fallback, asymmetric gating [VERIFIED sentinel/tests/test_detection.py:1-396] | `pytest tests/test_detection.py` |
| `sentinel/tests/test_gateway.py` | 11 | API Gateway Endpoints: Root web GUI (`/`), `/health`, `/api/v1/inspect`, `/api/v1/stats`, `/v1/chat/completions` (clean prompt ALLOW, attack prompt BLOCK), `/api/v1/events`, `/api/v1/rules`, SSE streaming chat completions, Gemini upstream routing and missing key handling [VERIFIED sentinel/tests/test_gateway.py:1-175] | `pytest tests/test_gateway.py` |
| `sentinel/tests/test_malware_scanner.py` | 13 | Pillar I: Shannon byte entropy bounds, padding dilution resilience, MalConv byte-to-tensor conversion, MalImg 2D texture tensor conversion, static PE/ELF/Mach-O heuristics, MalConv inference, MalImg ResNet-18 family classification, consensus judge override rules, `/api/v1/scan-file` API [VERIFIED sentinel/tests/test_malware_scanner.py:1-212] | `pytest tests/test_malware_scanner.py` |
| `sentinel/tests/test_redteam.py` | 28 | Pillar V: Syntactic mutators (Base64, Leetspeak, Rot13, homoglyphs), Strategist neural framing templates, TAP-Lite beam search tree exploration, token cosine similarity pruning, Auditor Evaluative Judge tiers (canary regex, refusal patterns, dangerous tool output, windowed LCS ratio), closed-loop immunization and rule promotion, FastAPI redteam endpoints [VERIFIED sentinel/tests/test_redteam.py:1-391] | `pytest tests/test_redteam.py` |
| `sentinel/tests/test_security_vectors.py` | 12 | Pillar IV Vectors: CanaryEngine token generation, prompt injection, exfiltration leak detection; RAGScanner overlapping sliding window chunking, clean vs poisoned chunk quarantine; ThreatIntelligenceFeed TF-IDF n-gram extraction, signature synthesis, dynamic hot-reload; VoiceClient synthetic WAV creation and offline fallback [VERIFIED sentinel/tests/test_security_vectors.py:1-210] | `pytest tests/test_security_vectors.py` |
| `sentinel/tests/test_tool_guardrail.py` | 21 | Pillar IV Guardrails: SSRF protection against cloud metadata (`169.254.169.254`), decimal IP evasion, hex IP evasion, mixed octal-decimal IP, Alibaba/Azure metadata endpoints, localhost/loopback; AST normalizer shell reverse shells, GTFOBins abuse, SQL sleep, oversize padding fail-closed; `/api/v1/inspect-tool` API [VERIFIED sentinel/tests/test_tool_guardrail.py:1-169] | `pytest tests/test_tool_guardrail.py` |
| `sentinel/tests/test_vision.py` | 29 | Pillar III: Image RGB canonicalization, Otsu binarization and text presence gate, Mock OCR driver fixtures and OCR factory fallback, MobileCLIP vision tower forward pass, concept bank cosine scoring, SRM filter bank kernels, PGD noise variance detector, LSB chi-square steganography, CIE $\Delta E$ color distance, micro-font and off-canvas rules, PDF/DOCX hidden text parsers, solid-mask redactor, consensus judge [VERIFIED sentinel/tests/test_vision.py:1-492] | `pytest tests/test_vision.py` |

---

## 2. Benchmark Scripts & Datasets

### 1. Full 662 Samples Benchmark (`benchmark_full_662.py`)
- **Script Path**: `sentinel/tests/benchmark_full_662.py` [VERIFIED sentinel/tests/benchmark_full_662.py:1-175]
- **Target Dataset**: `deepset/prompt-injections` from HuggingFace (combines test split of 116 samples and train split of 546 samples) [VERIFIED sentinel/tests/benchmark_full_662.py:25-65].
- **Local Dataset File**: `sentinel/tests/samples/benchmark_deepset_all_662.json` [VERIFIED sentinel/tests/benchmark_full_662.py:21].
  - File Size / Line Count: 3,312 lines, 662 JSON objects [VERIFIED command output].
  - Composition: **263 adversarial prompt-injection attacks** and **399 benign prompts** [VERIFIED sentinel/tests/samples/benchmark_report_deepset_all_662.json:4-5].
- **Stored Result Report**: `sentinel/tests/samples/benchmark_report_deepset_all_662.json` [STORED RESULT sentinel/tests/samples/benchmark_report_deepset_all_662.json:1-17].
  - Exact Stored Metrics:
    - `"dataset": "deepset/prompt-injections (full)"`
    - `"total_samples": 662`
    - `"attacks_count": 263`
    - `"benign_count": 399`
    - `"accuracy_pct": 75.83`
    - `"precision_pct": 96.4`
    - `"recall_pct": 40.68`
    - `"f1_score": 0.5722`
    - `"false_positive_rate_pct": 1.0`
    - `"avg_latency_ms": 678.02`
    - `"execution_time_sec": 448.87`
    - `"tp": 107`
    - `"tn": 395`
    - `"fp": 4`
    - `"fn": 156`

### 2. 300-Sample Evaluation Benchmark (`benchmark_expanded.py`)
- **Script Path**: `sentinel/tests/benchmark_expanded.py` [VERIFIED sentinel/tests/benchmark_expanded.py:1-188]
- **Local Dataset File**: `sentinel/tests/samples/benchmark_deepset_300.json` (1,502 lines, 300 samples: 150 attacks, 150 benign) [VERIFIED command output].
- **Stored Result Report**: `sentinel/tests/samples/benchmark_report_deepset.json` [STORED RESULT sentinel/tests/samples/benchmark_report_deepset.json:1-14].
  - Exact Stored Metrics:
    - `"dataset": "deepset/prompt-injections"`
    - `"sample_size": 300`
    - `"accuracy_pct": 73.0`
    - `"precision_pct": 100.0`
    - `"recall_pct": 46.0`
    - `"f1_score": 0.6301`
    - `"false_positive_rate_pct": 0.0`
    - `"avg_latency_ms": 711.13`
    - `"tp": 69`
    - `"tn": 150`
    - `"fp": 0`
    - `"fn": 81`

### 3. Core 40-Sample Dissertation Benchmark (`benchmark_detection.py`)
- **Script Path**: `sentinel/tests/benchmark_detection.py` [VERIFIED sentinel/tests/benchmark_detection.py:1-110]
- **Local Dataset File**: `sentinel/tests/samples/benchmark_dataset.json` (43 lines, 40 samples) [VERIFIED sentinel/tests/samples/benchmark_dataset.json:1-43].
  - Composition: 20 benign prompts (science, literature, coding) and 20 adversarial prompts (DAN jailbreaks, Base64 encodings, canary exfiltration probes, grandma roleplay) [VERIFIED sentinel/tests/samples/benchmark_dataset.json:2-42].
- **Metrics Calculated**: Accuracy, Precision, Recall, F1 Score, Confusion Matrix (TP, FP, TN, FN), and Sub-Agent Latency breakdowns (overall, pattern, semantic, behavioral) [VERIFIED sentinel/tests/benchmark_detection.py:30-105].

---

## 3. Stored Historical Performance Reports vs Fresh Measurement Requirements

| Performance Metric | Stored Result Status in Repo | Exact Stored Value & Source File | Re-Run Required? |
| :--- | :--- | :--- | :--- |
| **"96.4% precision across 662 samples"** | **STORED RESULT FOUND** | Precision: `96.4%`, FPR: `1.0%`, TP: `107`, TN: `395`, FP: `4`, FN: `156`, Latency: `678.02 ms` in `sentinel/tests/samples/benchmark_report_deepset_all_662.json:1-17` [STORED RESULT] | No fresh run needed; value is recorded in stored benchmark JSON report |
| **"1.0% false-positive rate across 662 samples"** | **STORED RESULT FOUND** | False positive rate: `1.0%` (4 false positives out of 399 benign prompts) in `sentinel/tests/samples/benchmark_report_deepset_all_662.json:10` [STORED RESULT] | No fresh run needed; verified in stored report |
| **"100.0% precision on 300 deepset samples"** | **STORED RESULT FOUND** | Precision: `100.0%`, FPR: `0.0%` in `sentinel/tests/samples/benchmark_report_deepset.json:1-14` [STORED RESULT] | No fresh run needed |
| **"Canary detection under 0.01ms"** | **MEASUREMENT NOT STORED AS BENCHMARK FILE** | Code implements `canary_token in text` substring search in `sentinel/core/security_vectors/canary.py:53`. The sub-0.01ms claim is an architectural characteristic of Python C-string search, but no stored micro-benchmark log file exists | **Fresh measurement required** to prove wall-clock latency under 0.01ms on specific hardware |
| **"TF-IDF threat intel synthesis under 150ms"** | **MEASUREMENT NOT STORED AS BENCHMARK FILE** | Code runs Scikit-Learn `TfidfVectorizer.fit_transform` on up to 100 prompts in `sentinel/core/security_vectors/threat_feed.py:59-80`. No stored JSON timing report exists | **Fresh measurement required** to prove execution time under 150ms on specific hardware |
| **"DeBERTa inference latency ~20-40ms on MPS"** | **MEASUREMENT NOT STORED AS BENCHMARK FILE** | Average latency on full 662 run was `678.02 ms` (which included Stage 2 arbiter calls on gray-zone prompts) [STORED RESULT sentinel/tests/samples/benchmark_report_deepset_all_662.json:11] | **Fresh measurement required** for isolated DeBERTa MPS forward pass |
