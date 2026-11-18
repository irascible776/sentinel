# 01 Overview & System Structure

## 1. System Purpose
Sentinel is an inline AI Security Gateway and runtime enforcement proxy deployed in front of Large Language Model (LLM) endpoints [VERIFIED sentinel/core/gateway/app.py:101-325]. Its primary purpose is to inspect, sanitize, intercept, or block malicious payloads crossing the application boundary in both ingress (user-to-model) and egress (model-to-user) directions [VERIFIED sentinel/core/gateway/app.py:115-325].

Sentinel addresses multi-modal and multi-vector threats:
1. **Ingress Prompt Injection & Jailbreaks**: Direct jailbreak attempts, roleplay bypasses, system instruction overrides, and linguistic evasions [VERIFIED sentinel/core/detection/pattern_hunter.py:18-80; sentinel/core/detection/semantic_analyst.py:32-75].
2. **Indirect Prompt Injection**: Malicious instructions embedded inside retrieved documents, web DOMs, or external files [VERIFIED sentinel/core/security_vectors/rag_scanner.py:27-104].
3. **Agentic Tool Call Exploitation & SSRF**: Model-generated tool call invocations containing Server-Side Request Forgery targets (cloud metadata IPs, decimal/hex encoded IPs, private subnets) or command injections (reverse shells, GTFOBins, SQL injection) [VERIFIED sentinel/core/detection/tool_guardrail.py:46-248; sentinel/core/detection/guardrails/ssrf_filter.py:25-188].
4. **Malicious Binary Smuggling**: Executable payloads (PE, ELF, Mach-O) disguised as benign attachments or training data [VERIFIED sentinel/core/malware/heuristics.py:20-274; sentinel/core/malware/engine.py:45-165].
5. **Code Security Vulnerabilities & Secrets**: Tainted code generation containing SQL injection, OS command injection, pickle deserialization, or hardcoded secrets/credentials [VERIFIED sentinel/core/codesec/ast_parser.py:50-480; sentinel/core/codesec/secret_scanner.py:40-270].
6. **Visual & Document Steganography**: Text embedded invisibly via micro-fonts, zero-opacity layers, off-canvas placement, LSB steganography, or PGD high-frequency adversarial perturbations [VERIFIED sentinel/core/vision/document/hidden_text_rules.py:30-170; sentinel/core/vision/srm/lsb_detector.py:15-108; sentinel/core/vision/srm/pgd_detector.py:20-137].
7. **System Prompt Exfiltration & Egress Leakage**: Sensitive instructions leaked by the LLM or canary honeytokens revealed in completions [VERIFIED sentinel/core/security_vectors/canary.py:15-53; sentinel/core/gateway/stream_interceptor.py:40-125].

---

## 2. Threat Model
The threat model encompasses five distinct threat actors and interaction vectors:
- **Direct User / Adversary**: Sends handcrafted jailbreaks, leetspeak, Base64 encodings, or conversational manipulation over `/v1/chat/completions` or `/api/v1/inspect` [VERIFIED sentinel/core/gateway/app.py:101-367].
- **Untrusted RAG / Data Repository**: An attacker poisons documents ingested into a vector store to hijack downstream LLM context [VERIFIED sentinel/core/security_vectors/rag_scanner.py:27-104].
- **Autonomous Tool Execution Environment**: An LLM agent issues function calls with crafted arguments targeting internal infrastructure or executing arbitrary system commands [VERIFIED sentinel/core/detection/tool_guardrail.py:46-248].
- **Compromised Upstream / Output Generation**: An upstream LLM emits sensitive data (API keys, PII, canary tokens) or vulnerable code payloads [VERIFIED sentinel/core/gateway/stream_interceptor.py:40-125; sentinel/core/gateway/dlp.py:15-53].
- **Multimodal Payload Ingestion**: An attacker embeds visual adversarial triggers or hidden text inside images, PDFs, or DOCX documents processed by multimodal pipelines [VERIFIED sentinel/core/vision/engine.py:75-350].

---

## 3. Position in Traffic Path
Sentinel operates as an inline reverse proxy sitting directly between the client application and upstream LLM providers [VERIFIED sentinel/core/gateway/app.py:101-325; sentinel/core/gateway/proxy.py:11-120].

```
[ Client Application / Extension / Voice Client ]
                     │
                     ▼
       ┌───────────────────────────┐
       │   Sentinel Ingress Proxy  │  FastAPI (Port 8000)
       │  (/v1/chat/completions)   │
       └─────────────┬─────────────┘
                     │
         [ Ingress Detection Pipeline ]
         ├── Pattern Hunter (Regex)
         ├── Semantic Analyst (DeBERTa-v3)
         ├── Behavioral Profiler (Session sliding window)
         └── Stage 2 Arbiter (Llama-3.2 GGUF / Cloud LLM)
                     │
            Decision: BLOCK? ──► [HTTP 403 / JSON Block Response]
                     │
            Decision: ALLOW
                     │
                     ▼
       ┌───────────────────────────┐
       │  Canary Honeytoken Inject │  Appends CANARY-SECRET-<uuid> to system prompt
       └─────────────┬─────────────┘
                     │
                     ▼
       ┌───────────────────────────┐
       │     Upstream Dispatch     │  HTTPX AsyncClient
       └─────────────┬─────────────┘
                     │
       ┌─────────────┴─────────────┐
       ▼                           ▼
[ Google Gemini ]         [ OpenAI / Ollama / Mock ]
       │                           │
       └─────────────┬─────────────┘
                     │
                     ▼
       ┌───────────────────────────┐
       │ Egress Stream Interceptor │  SSE chunk evaluation
       │ & DLP Regex Redactor      │  Circuit breaker on canary leak / attack patterns
       └─────────────┬─────────────┘
                     │
                     ▼
         [ Sanitized Client Stream ]
```

---

## 4. Tech Stack

### Runtime & Core Frameworks
- **Python**: 3.12.3 [VERIFIED command: `python3 --version` -> `Python 3.12.3`]
- **Web Framework**: FastAPI `0.141.1` [VERIFIED command: `python3 -m pip freeze | grep fastapi` -> `fastapi==0.141.1`]
- **ASGI Server**: Uvicorn `0.53.0` [VERIFIED command: `python3 -m pip freeze | grep uvicorn` -> `uvicorn==0.53.0`]
- **Base ASGI**: Starlette `1.6.0` [VERIFIED command: `python3 -m pip freeze | grep starlette` -> `starlette==1.6.0`]
- **Settings & Validation**: Pydantic `2.13.5`, Pydantic-Settings `2.15.0` [VERIFIED command: `python3 -m pip freeze | grep pydantic` -> `pydantic==2.13.5`, `pydantic-settings==2.15.0`]
- **HTTP Client**: HTTPX `0.28.1`, HTTPX-SSE `0.4.3` [VERIFIED command: `python3 -m pip freeze | grep httpx` -> `httpx==0.28.1`, `httpx-sse==0.4.3`]
- **Persistence**: SQLite with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) via SQLAlchemy `2.0.54` [VERIFIED sentinel/core/gateway/database.py:34-40; command: `python3 -m pip freeze | grep SQLAlchemy` -> `SQLAlchemy==2.0.54`]

### Machine Learning & NLP
- **Deep Learning Framework**: PyTorch `2.14.0+cpu` [VERIFIED command: `python3 -m pip freeze | grep torch` -> `torch==2.14.0+cpu`]
- **Transformers**: HuggingFace Transformers `5.17.0`, Tokenizers `0.23.2` [VERIFIED command: `python3 -m pip freeze | grep -E "transformers|tokenizers"` -> `transformers==5.17.0`, `tokenizers==0.23.2`]
- **ML Utilities**: Scikit-Learn `1.9.1`, SciPy `1.18.1`, NumPy `2.5.3` [VERIFIED command: `python3 -m pip freeze | grep -E "scikit-learn|scipy|numpy"` -> `scikit-learn==1.9.1`, `scipy==1.18.1`, `numpy==2.5.3`]
- **Model Storage**: SafeTensors `0.8.0` [VERIFIED command: `python3 -m pip freeze | grep safetensors` -> `safetensors==0.8.0`]
- **GGUF Runtime Dependency**: `llama-cpp-python>=0.2.56` specified in requirements [VERIFIED sentinel/requirements.txt:20]

### Document & Vision Processing
- **Image Processing**: Pillow `10.2.0` [VERIFIED command: `python3 -m pip freeze | grep pillow` -> `pillow==10.2.0`]
- **PDF Extraction**: PyMuPDF (`fitz`) `1.28.2` [VERIFIED command: `python3 -m pip freeze | grep pymupdf` -> `pymupdf==1.28.2`]
- **DOCX Parsing**: Python-Docx `1.2.0` [VERIFIED command: `python3 -m pip freeze | grep python-docx` -> `python-docx==1.2.0`]

### Testing & Observability
- **Test Runner**: Pytest `9.1.1`, Pytest-Asyncio `1.4.0` [VERIFIED command: `python3 -m pip freeze | grep pytest` -> `pytest==9.1.1`, `pytest-asyncio==1.4.0`]
- **Dashboard**: Streamlit `1.65.0` [VERIFIED command: `python3 -m pip freeze | grep streamlit` -> `streamlit==1.65.0`]

---

## 5. Per-Module Purpose & Code Size

| Module Directory | Python LOC | Total LOC (inc. assets/configs) | Purpose |
| :--- | :--- | :--- | :--- |
| `sentinel/core/gateway` | 1,706 | 4,508 | Reverse proxy, `/v1/chat/completions` endpoint, SSE stream interceptor, DLP, SQLite WAL audit logging, static web GUI [VERIFIED command output] |
| `sentinel/core/detection` | 2,230 | 2,380 | Ingress multi-agent cascaded defense (PatternHunter, SemanticAnalyst, BehavioralProfiler, Stage2Arbiter, JudgeAgent), normalizer, SSRF filter, tool guardrails [VERIFIED command output] |
| `sentinel/core/malware` | 1,206 | 1,206 | Pillar I binary malware analysis (static heuristics, Shannon sliding entropy, MalConv 1D CNN, MalImg 2D CNN, consensus judge) [VERIFIED command output] |
| `sentinel/core/codesec` | 1,518 | 1,518 | Pillar II code vulnerability scanner (Python AST visitor, multilanguage structural regex lexer, Shannon entropy secret scanner, CodeBERT classification head) [VERIFIED command output] |
| `sentinel/core/vision` | 2,993 | 2,993 | Pillar III vision and document threat parser (SRM 30-filter bank, PGD perturbation detector, LSB stego detector, PDF/DOCX hidden text rules, OCR factory, MobileCLIP semantic scorer, redaction) [VERIFIED command output] |
| `sentinel/core/security_vectors` | 529 | 529 | Pillar IV runtime vectors: Canary honeytoken engine, RAG overlapping chunk scanner, TF-IDF threat intel feed, Whisper voice attack client bridge [VERIFIED command output] |
| `sentinel/core/redteam` | 1,741 | 1,922 | Pillar V automated AI red-teaming (TAP-Lite beam search, LLM strategist mutator, syntactic mutators, multi-target adapters, hardening rule synthesizer) [VERIFIED command output] |
| `sentinel/dashboard` | 1,376 | 1,376 | SOC real-time telemetry dashboard in Streamlit [VERIFIED command output] |
| `sentinel/extension` | 0 | 386 | Chrome browser extension (Manifest V3, popup.html, content.js, background.js) [VERIFIED command output] |
| `sentinel/scripts` | 559 | 559 | Model downloaders and end-to-end pillar verification script [VERIFIED command output] |
| `sentinel/tests` | 2,704 | 8,657 | Unit tests, mock suites, benchmarks, and JSON datasets [VERIFIED command output] |

---

## 6. Per-Pillar Implementation Status

| Pillar | Focus | Implementation Status | Core LOC | Test Count | Key Evidence Files |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Ingress Multi-Agent Defense** | Direct Prompt Injection & Jailbreaks | **Implemented** | 2,230 | 25 | `sentinel/core/detection/judge.py:40-310`, `sentinel/tests/test_detection.py` [VERIFIED] |
| **Pillar I** | Malware Binary Analysis | **Implemented** | 1,206 | 13 | `sentinel/core/malware/engine.py:45-205`, `sentinel/tests/test_malware_scanner.py` [VERIFIED] |
| **Pillar II** | Code Security & AST Vulnerability Detection | **Implemented** | 1,518 | 30 | `sentinel/core/codesec/engine.py:35-195`, `sentinel/tests/test_code_security.py` [VERIFIED] |
| **Pillar III** | Vision & Document Threat Engine | **Implemented** | 2,993 | 29 | `sentinel/core/vision/engine.py:75-350`, `sentinel/tests/test_vision.py` [VERIFIED] |
| **Pillar IV** | Agentic Runtime Guardrails & Security Vectors | **Implemented** | 1,010 | 35 | `sentinel/core/detection/tool_guardrail.py:46-248`, `sentinel/core/security_vectors/canary.py:15-53`, `sentinel/tests/test_tool_guardrail.py`, `sentinel/tests/test_security_vectors.py`, `sentinel/tests/test_components.py` [VERIFIED] |
| **Pillar V** | Automated AI Red-Teaming (TAP-Lite) | **Implemented** | 1,741 | 28 | `sentinel/core/redteam/search.py:30-285`, `sentinel/core/redteam/runner.py:35-220`, `sentinel/tests/test_redteam.py` [VERIFIED] |
| **Gateway Infrastructure** | Reverse Proxy, Interceptor, Database | **Implemented** | 1,706 | 11 | `sentinel/core/gateway/app.py:101-325`, `sentinel/core/gateway/proxy.py:11-120`, `sentinel/tests/test_gateway.py` [VERIFIED] |

Total test count across all test files: **171 tests** [VERIFIED command: `cd sentinel && python3 -m pytest --collect-only -q`].

---

## 7. Discrepancies (Docs vs Code)
1. **Pillar Count in Spec vs Repo**:
   - `Sentinel v2.0 - Scope Expansion Spec.md:32-38` lists 5 pillars (I: Malware, II: Code Security, III: Vision & Document, IV: Agentic Guardrails, V: Automated Red-Teaming) [STORED RESULT sentinel/Sentinel v2.0 - Scope Expansion Spec.md:32-38].
   - In code, the original core prompt injection defense is implemented inside `sentinel/core/detection` alongside Pillar IV tool guardrails, meaning there are 6 distinct security subsystems in active code [VERIFIED sentinel/core/detection/judge.py:40-310; sentinel/core/detection/tool_guardrail.py:46-248].
2. **Audio Deepfake Detection**:
   - `sentinel/br1_plan/05_Voice_Attack_Surface.md:1-70` describes audio attack surfaces and voice testing.
   - `Sentinel v2.0 - Scope Expansion Spec.md:23-25` explicitly states "Pillar III's audio deepfake detection was dropped — different data modality, different model family... scoped to vision/document threats only" [STORED RESULT sentinel/Sentinel v2.0 - Scope Expansion Spec.md:23-25].
   - Code reality: Audio deepfake classification is NOT implemented; `sentinel/core/security_vectors/voice_client.py:28-150` implements only a client-side audio capture and transcription bridge calling Whisper or mock audio for STT prompt injection testing [VERIFIED sentinel/core/security_vectors/voice_client.py:28-150].
