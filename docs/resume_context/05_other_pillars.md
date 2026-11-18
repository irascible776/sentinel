# 05 Detailed Audit of Specialized Security Pillars

This section audits the remaining functional security pillars, application-plane defenses, security vectors, interfaces, and tools in Sentinel.

---

## 1. Pillar II: Code Security & AST Vulnerability Engine (`sentinel/core/codesec/`)
- **Implementation Status**: **Implemented** [VERIFIED sentinel/core/codesec/engine.py:35-195]
- **Core LOC**: 1,518 Python LOC [VERIFIED command output]
- **Unit Test Count**: 30 tests in `sentinel/tests/test_code_security.py` [VERIFIED command output]

### Supported Languages & Parsers
- Supported Languages: Python, JavaScript, Java, C, C++, Go, PHP (`SUPPORTED_LANGUAGES = ["python", "javascript", "java", "c", "cpp", "go", "php"]`) [VERIFIED sentinel/core/codesec/config.py:37].
- **Python AST Parser**: Native `ast.parse` with AST depth recursion protection (`MAX_AST_DEPTH = 100`) and size limits (`MAX_CODE_SIZE_BYTES = 1048576` = 1 MB, `MAX_CODE_LINES = 5000`) [VERIFIED sentinel/core/codesec/config.py:50-52; sentinel/core/codesec/ast_parser.py:50-120].
- **Multi-Language Regex Lexer**: Structural regex pattern matching for non-Python languages to detect raw string interpolations in SQL and command execution calls [VERIFIED sentinel/core/codesec/ast_parser.py:270-430].

### AST Taint Flow Analysis (Python)
Tracks data flows from sources to sinks:
- **Taint Sources**: Function parameters, outer dynamic variables, environmental inputs [VERIFIED sentinel/core/codesec/ast_parser.py:65-150].
- **Taint Cleansing**: Reassignment to literal constants or parameterized sanitizers removes taint [VERIFIED sentinel/core/codesec/ast_parser.py:85-110].
- **Dangerous Sinks**:
  - **SQL Injection (CWE-89)**: `cursor.execute`, `connection.execute`, raw SQL string format/f-string interpolation with dynamic taint [VERIFIED sentinel/core/codesec/ast_parser.py:155-210].
  - **OS Command Injection (CWE-78)**: `os.system`, `os.popen`, `subprocess.Popen`, `subprocess.run`, `subprocess.call` with shell=True or unescaped variables [VERIFIED sentinel/core/codesec/ast_parser.py:215-265].
  - **Insecure Deserialization (CWE-502)**: `pickle.loads`, `_pickle.loads`, `yaml.load(..., Loader=yaml.Loader)` without SafeLoader, `eval()`, `exec()` [VERIFIED sentinel/core/codesec/ast_parser.py:270-320].
- **Suppression Mechanism**: Respects inline `# nosec` annotations by attributing them to specific lines and lowering their active policy action to QUARANTINE/LOG without triggering direct Tier 1 BLOCK [VERIFIED sentinel/core/codesec/ast_parser.py:115-135; sentinel/core/codesec/judge.py:57-61].

### High-Entropy Secret Scanner (CWE-798)
- File: `sentinel/core/codesec/secret_scanner.py` [VERIFIED sentinel/core/codesec/secret_scanner.py:1-272]
- **Rule Count**: 5 distinct detection rules:
  1. `AWS_KEY_PATTERN`: `\b((?:AKIA|ASIA)[0-9A-Z]{16})\b` [VERIFIED sentinel/core/codesec/secret_scanner.py:25]
  2. `GITHUB_PAT_PATTERN`: `\b(gh[pousr]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b` [VERIFIED sentinel/core/codesec/secret_scanner.py:26]
  3. `PEM_KEY_PATTERN`: `-----BEGIN ([A-Z ]+)?PRIVATE KEY(?: BLOCK)?-----` [VERIFIED sentinel/core/codesec/secret_scanner.py:27]
  4. `JWT_PATTERN`: `\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b` validated by Base64URL header decode confirming JSON `"alg"` [VERIFIED sentinel/core/codesec/secret_scanner.py:28, 94-115]
  5. `SENSITIVE_ASSIGNMENT_PATTERN`: Regex for variables matching `api_key|secret_key|private_key|token|password|credentials` coupled with Shannon entropy analysis [VERIFIED sentinel/core/codesec/secret_scanner.py:31-37]
- **Shannon Entropy Calculation**:
  $$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$
  [VERIFIED sentinel/core/codesec/secret_scanner.py:57-67]. Threshold: `MIN_SECRET_ENTROPY = 3.8` bits per char; length bounds: `16` to `512` chars [VERIFIED sentinel/core/codesec/config.py:56-58].
- **False-Positive Filtering**: Checks candidates against 11 documentation sample placeholders (e.g., `akiaiosfodnn7example`, `your_api_key_here`, UUIDs, URLs, template syntax) [VERIFIED sentinel/core/codesec/secret_scanner.py:40-91].

### 3-Tier Precedence Judge
- File: `sentinel/core/codesec/judge.py:CodeSecurityJudge` [VERIFIED sentinel/core/codesec/judge.py:26-177]
- **Tier 1 (High-Confidence Known-Bad Overrides)**: Direct unsuppressed SQLi, RCE, pickle deserialization, or verified structural secrets -> immediate `BLOCK`, risk score $\ge 95.0$ [VERIFIED sentinel/core/codesec/judge.py:62-79].
- **Tier 2 (High-Confidence Known-Good Overrides)**: Clean code with zero findings or properly suppressed `# nosec` -> `ALLOW`, risk score $\le 15.0$ [VERIFIED sentinel/core/codesec/judge.py:81-110].
- **Tier 3 (Calibrated Ensemble)**:
  $$\text{Composite Risk} = 0.35 \times \text{AST} + 0.45 \times \text{CodeBERT} + 0.20 \times \text{Secrets}$$
  [VERIFIED sentinel/core/codesec/config.py:45-47; sentinel/core/codesec/judge.py:115-135].

---

## 2. Pillar III: Vision & Document Threat Engine (`sentinel/core/vision/`)
- **Implementation Status**: **Implemented** [VERIFIED sentinel/core/vision/engine.py:75-350]
- **Core LOC**: 2,993 Python LOC [VERIFIED command output]
- **Unit Test Count**: 29 tests in `sentinel/tests/test_vision.py` [VERIFIED command output]

### Architecture & Components
1. **Preprocessing**:
   - `image_prep.py`: EXIF metadata stripping, RGB canonicalization, max dimension capping (2048px) [VERIFIED sentinel/core/vision/preprocessing/image_prep.py:40-105].
   - `text_presence.py`: Fast pre-OCR gate using Otsu threshold binarization and edge density calculation (<5% text edge density skips heavy OCR pipelines) [VERIFIED sentinel/core/vision/preprocessing/text_presence.py:25-95].
2. **OCR Engine Chain**:
   - Factory pattern (`factory.py`) with capability probing: checks parameter override -> config override -> `EasyOCR` (CRAFT+CRNN) -> `PyTesseract` -> `MockOCRDriver` [VERIFIED sentinel/core/vision/ocr/factory.py:25-75].
3. **Spatial Rich Model (SRM) Filter Bank**:
   - File: `sentinel/core/vision/srm/kernels.py` [VERIFIED sentinel/core/vision/srm/kernels.py:12-186].
   - Non-trainable PyTorch Conv2d layer initialized with **10 Spatial Rich Model residual kernels** (1st-order differences, 2nd-order Laplacians, 5x5 edge inhibitors) padded to 5x5 [VERIFIED sentinel/core/vision/srm/kernels.py:12-18, 157-185].
   - Clamps residuals to $[-T, T]$ where $T = 3.0$ (`SRM_QUANTIZATION_TRUNCATION_T = 3.0`) [VERIFIED sentinel/core/vision/config.py:29; sentinel/core/vision/srm/kernels.py:184].
4. **LSB Steganography Detector**:
   - File: `sentinel/core/vision/srm/lsb_detector.py` [VERIFIED sentinel/core/vision/srm/lsb_detector.py:20-108].
   - Implements Westfeld & Pfitzmann Chi-Square test on Pairs of Values (PoVs: $2k, 2k+1$) across pixel histograms [VERIFIED sentinel/core/vision/srm/lsb_detector.py:20-55].
   - Computes survival function (p-value) via `scipy.stats.chi2.sf(chi_stat, k)`. If $p > 0.95$, flags as LSB steganographic carrier [VERIFIED sentinel/core/vision/srm/lsb_detector.py:75-85; sentinel/core/vision/config.py:33].
5. **PGD Adversarial Perturbation Detector**:
   - File: `sentinel/core/vision/srm/pgd_detector.py` [VERIFIED sentinel/core/vision/srm/pgd_detector.py:20-137].
   - Computes residual variance and high-frequency energy ratio across SRM residual channels to detect imperceptible gradient-based adversarial noise [VERIFIED sentinel/core/vision/srm/pgd_detector.py:60-110].
6. **Document Hidden-Text Forensic Parsers**:
   - PDF Parser (`pdf_parser.py` via PyMuPDF) and DOCX Parser (`docx_parser.py` via python-docx) [VERIFIED sentinel/core/vision/document/pdf_parser.py:30-175; sentinel/core/vision/document/docx_parser.py:25-120].
   - Structural Oracles (`hidden_text_rules.py`):
     - PDF Render Mode 3 (transparent invisible text) [VERIFIED sentinel/core/vision/document/pdf_parser.py:90].
     - Micro-fonts $\le 1.8\text{ pt}$ or $< 0.20$ of median page font size [VERIFIED sentinel/core/vision/config.py:38-39].
     - Low-contrast white-on-white text: Euclidean CIE $\Delta E \le 4.5$ computed in CIE L\*a\*b\* color space [VERIFIED sentinel/core/vision/document/hidden_text_rules.py:17, 56-65].
     - Off-canvas text: bounding boxes located completely outside visible page CropBox [VERIFIED sentinel/core/vision/document/hidden_text_rules.py:130-155].
     - OOXML `<w:vanish>` hidden-run flags in DOCX [VERIFIED sentinel/core/vision/document/docx_parser.py:65-80].
7. **Redaction Engine**:
   - File: `sentinel/core/vision/redaction/redactor.py` [VERIFIED sentinel/core/vision/redaction/redactor.py:20-94].
   - Draws non-reversible solid charcoal rectangles (`(24, 24, 27)`) over injection bounding boxes with 4px padding and `[SENTINEL REDACTED]` watermark [VERIFIED sentinel/core/vision/config.py:53-55; sentinel/core/vision/redaction/redactor.py:30-65].
8. **Consensus Judge**:
   - File: `sentinel/core/vision/consensus/judge.py:VisionJudge` [VERIFIED sentinel/core/vision/consensus/judge.py:24-167].
   - Two-layer corroboration: canary hits and high-confidence OCR signatures (`SIG-001`, `SIG-002`) immediately trigger `BLOCK` [VERIFIED sentinel/core/vision/consensus/judge.py:47-70].
   - Soft channels (stego/noise) without text confirmation are clamped at `FLAG` (max score 65.0) to enforce zero false positives on benign images [VERIFIED sentinel/core/vision/config.py:48; sentinel/core/vision/consensus/judge.py:120-145].

---

## 3. Pillar V: Automated AI Red-Teaming Squad (`sentinel/core/redteam/`)
- **Implementation Status**: **Implemented** [VERIFIED sentinel/core/redteam/runner.py:35-220]
- **Core LOC**: 1,741 Python LOC (1,922 total inc. seed data) [VERIFIED command output]
- **Unit Test Count**: 28 tests in `sentinel/tests/test_redteam.py` [VERIFIED command output]

### Architecture & Agents
1. **Agent 1: Orchestrator & TAP-Lite Search Engine (`search.py`)**:
   - Implements Tree of Attacks with Pruning (TAP-Lite) beam search [VERIFIED sentinel/core/redteam/search.py:45-285].
   - Constants: `beam_width = 3`, `branch_factor = 2`, `max_depth = 4`, `intent_threshold = 0.50` [VERIFIED sentinel/core/redteam/search.py:55-59].
   - Genealogical Lineage Tracking: Tracks branching parentage (`parent_lineage.b_idx`) across beam ranking [VERIFIED sentinel/core/redteam/search.py:49, 130-160].
   - Pruning: Computes token cosine similarity via `compute_token_cosine_similarity`. If similarity to seed prompt $< 0.50$, prunes node as off-topic [VERIFIED sentinel/core/redteam/search.py:22-42, 172-180].
2. **Agent 2: Syntactic Obfuscator (`mutators/syntactic.py`)**:
   - Rule-based mutators: Base64 wrapping, Leetspeak translation, Zero-width space insertion, Rot13 encoding, and Unicode homoglyph injection [VERIFIED sentinel/core/redteam/mutators/syntactic.py:20-140].
3. **Agent 3: Neural Strategist (`mutators/strategist.py`)**:
   - Neural persona framing powered by local Google Gemma-2-2B-IT GGUF on Metal GPU [VERIFIED sentinel/core/redteam/mutators/strategist.py:57-85].
   - Fallback: 6 high-fidelity linguistic framing templates (`ACADEMIC_AUDITOR_FRAMING`, `COUNTERFACTUAL_SIMULATION`, `DUAL_CONTEXT_LAYERING`, `ETHICAL_RESEARCH_PERSONA`, `DEVELOPER_DEBUG_MODE`, `REVERSE_ROLE_INVERSION`) [VERIFIED sentinel/core/redteam/mutators/strategist.py:15-49].
4. **Agent 4: Evaluative Judge (`judge.py`)**:
   - 3-tier evaluation:
     - Tier 1: Deterministic check (canary token regex `sentinel-honey-[0-9a-f]{8}`, refusal patterns, dangerous tool outputs like `/bin/bash`, `169.254.169.254`, `AKIA...`) [VERIFIED sentinel/core/redteam/judge.py:16-39].
     - Tier 2: Windowed token Longest Common Subsequence (LCS) ratio ($\ge 0.70$) for system prompt leak extraction detection [VERIFIED sentinel/core/redteam/judge.py:42-65].
     - Tier 3: Category-anchored scoring (system prompt extraction, SSRF/RCE confirmation) [VERIFIED sentinel/core/redteam/judge.py:80-160].
5. **Target Adapters (`targets.py`)**:
   - `SentinelLocalTarget`: In-process Python connector to `JudgeAgent` with security key authentication (`REDTEAM_SERVICE_KEY` header verification) [VERIFIED sentinel/core/redteam/targets.py:40-120].
   - `OpenAITargetConnector`: Remote OpenAI-compatible endpoints [VERIFIED sentinel/core/redteam/targets.py:125-230].
   - `AnthropicTargetConnector`: Remote Claude API endpoints [VERIFIED sentinel/core/redteam/targets.py:235-340].
6. **Closed-Loop Immunization & Hardening (`hardening.py`)**:
   - Auto-synthesizes regex rules from successful red-team jailbreaks, assigns IDs (`AUTO-RULE-...`), stages in `SHADOW` mode, and provides promoting endpoint `/api/v1/redteam/rules/promote/{rule_id}` to make rules active [VERIFIED sentinel/core/redteam/hardening.py:30-230; sentinel/core/gateway/app.py:872-885].

---

## 4. Application-Plane & Egress Defenses

### Egress AST Analyzer (`sentinel/core/gateway/ast_analyzer.py`)
- **Status**: **Implemented** [VERIFIED sentinel/core/gateway/ast_analyzer.py:1-221]
- **Mechanism**: Static AST taint analysis on generated Python code inside LLM response streams [VERIFIED sentinel/core/gateway/ast_analyzer.py:4-21].
- **Dangerous Sources (16 categories)**: Keystroke/input hooks (`pynput`, `keyboard`, `GetAsyncKeyState`, `SetWindowsHookEx`), clipboard stealers (`pyperclip.paste`), screen capture (`mss`, `pyscreenshot`), browser cookie DBs (`sqlite3.connect`, `CryptUnprotectData`) [VERIFIED sentinel/core/gateway/ast_analyzer.py:30-45].
- **Dangerous Sinks (13 categories)**: Network sockets (`socket.send`), HTTP exfiltration (`requests.post`, `urllib.request.urlopen`, `aiohttp.ClientSession.post`), email (`smtplib.sendmail`), webhooks (`discord.Webhook`, `telegram.Bot`) [VERIFIED sentinel/core/gateway/ast_analyzer.py:50-65].
- **Violation Action**: Raises `TaintFlowViolation` if source-to-sink flow is detected, terminating the SSE response stream [VERIFIED sentinel/core/gateway/ast_analyzer.py:150-215; sentinel/core/gateway/stream_interceptor.py:94-111].

### Canary Honeytoken Engine (`sentinel/core/security_vectors/canary.py`)
- **Status**: **Implemented** [VERIFIED sentinel/core/security_vectors/canary.py:1-54]
- **Mechanism**: Injects unique `CANARY-SECRET-<uuid>` honeytoken into system prompt [VERIFIED sentinel/core/security_vectors/canary.py:15-31].
- **Detection**: Exact substring match in model output: `canary_token in text` [VERIFIED sentinel/core/security_vectors/canary.py:50-54].
- **Execution Speed**: Pure Python in-memory string search (`in` operator), running in microsecond timescales (<0.01ms) [VERIFIED sentinel/core/security_vectors/canary.py:53].

### Response-Side DLP Scanner (`sentinel/core/gateway/dlp.py`)
- **Status**: **Implemented** [VERIFIED sentinel/core/gateway/dlp.py:1-54]
- **Mechanism**: Scans completed responses for PII and secrets:
  - `EMAIL`: `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`
  - `CREDIT_CARD`: `\b(?:\d[ -]*?){13,16}\b`
  - `OPENAI_KEY`: `sk-[a-zA-Z0-9]{48}`
  - `GEMINI_KEY`: `AIzaSy[0-9A-Za-z-_]{33}`
  - `AWS_KEY`: `AKIA[0-9A-Z]{16}`
  - `CANARY`: Replaces with `[REDACTED CANARY TOKEN]` and logs critical event [VERIFIED sentinel/core/gateway/dlp.py:8-48].

### Streaming Circuit Breaker (`sentinel/core/gateway/stream_interceptor.py`)
- **Status**: **Implemented** [VERIFIED sentinel/core/gateway/stream_interceptor.py:1-128]
- **Mechanism**: Wraps SSE stream. Tracks sliding window of length 150 chars for canary leaks, and accumulates buffer crossing 500 chars for AST taint analysis. If either fires, halts stream, yields `[RESPONSE TERMINATED DUE TO POLICY VIOLATION]`, yields `[DONE]`, and logs `STREAM_CIRCUIT_BREAKER` event to DB [VERIFIED sentinel/core/gateway/stream_interceptor.py:68-111].

---

## 5. Security Vectors, Extension, Audio & Dashboard

### RAG Poisoning Scanner (`sentinel/core/security_vectors/rag_scanner.py`)
- **Status**: **Implemented** [VERIFIED sentinel/core/security_vectors/rag_scanner.py:1-138]
- **Chunking**: Overlapping sliding window: default `chunk_size = 500` chars, `overlap = 50` chars (`step = 450` chars) [VERIFIED sentinel/core/security_vectors/rag_scanner.py:51-75].
- **Inspection**: Evaluates each chunk via in-process `JudgeAgent.evaluate(chunk)`.
- **Quarantine**: If `risk_score >= 75.0` or `decision == "BLOCK"`, quarantines chunk and marks document as poisoned [VERIFIED sentinel/core/security_vectors/rag_scanner.py:85-98].

### Threat Intelligence Feed (`sentinel/core/security_vectors/threat_feed.py`)
- **Status**: **Implemented** [VERIFIED sentinel/core/security_vectors/threat_feed.py:1-185]
- **Clustering**: Extracts 2-gram to 4-gram phrases from blocked prompts using Scikit-Learn `TfidfVectorizer` [VERIFIED sentinel/core/security_vectors/threat_feed.py:52-80].
- **Signature Synthesis**: Converts top n-grams into regex signatures with token gap wildcards (`\bword1\s+(?:\w+\s+)*?word2\b`) and assigns default weight 35.0 [VERIFIED sentinel/core/security_vectors/threat_feed.py:90-120].
- **Hot Update**: Writes newly generated rules to `threat_rules.json`, triggering hot-reloading in `PatternHunter` [VERIFIED sentinel/core/security_vectors/threat_feed.py:130-175].

### Chrome Browser Extension (`sentinel/extension/`)
- **Status**: **Implemented** [VERIFIED sentinel/extension/manifest.json:1-34]
- **Manifest**: Manifest V3 extension for Chrome / Chromium browsers [VERIFIED sentinel/extension/manifest.json:2].
- **Permissions**: `activeTab`, `storage` [VERIFIED sentinel/extension/manifest.json:6].
- **Host Permissions**: `http://127.0.0.1:8000/*`, `http://localhost:8000/*`, `https://chatgpt.com/*`, `https://claude.ai/*` [VERIFIED sentinel/extension/manifest.json:7-12].
- **Content Script (`content.js`)**: Injects into ChatGPT/Claude DOM, intercepts textarea submission, forwards prompt to Sentinel `/api/v1/inspect`, and displays an inline warning/block overlay if injection is detected [VERIFIED sentinel/extension/content.js:20-145].

### Whisper Voice Attack Client (`sentinel/core/security_vectors/voice_client.py`)
- **Status**: **Implemented** [VERIFIED sentinel/core/security_vectors/voice_client.py:1-152]
- **Audio Capture**: Records microphone audio using `sounddevice` at 16,000 Hz or loads existing WAV files via `soundfile` [VERIFIED sentinel/core/security_vectors/voice_client.py:24, 75-120].
- **Transcription**: Uses HuggingFace pipeline with `openai/whisper-tiny` on CPU [VERIFIED sentinel/core/security_vectors/voice_client.py:37-43].
- **Ingress Testing**: Dispatches transcribed text to Sentinel `/v1/chat/completions` to test voice-to-text prompt injection vulnerability [VERIFIED sentinel/core/security_vectors/voice_client.py:125-148].

### SOC Telemetry Dashboard (`sentinel/dashboard/app.py`)
- **Status**: **Implemented** [VERIFIED sentinel/dashboard/app.py:1-1376]
- **LOC**: 1,376 Python LOC [VERIFIED command output]
- **Framework**: Streamlit `1.65.0` on port 8501 [VERIFIED sentinel/dashboard/app.py:9, 49; sentinel/run.py:97-111]
- **Features (10 Interactive Tabs)**:
  1. Live Attack Feed (real-time telemetry, auto-refresh 3s)
  2. Multi-Agent Inspector (drill-down per agent score)
  3. Canary Honeypot (active tokens and exfiltration logs)
  4. Threat Intelligence Feed (one-click clustering and rule compilation)
  5. RAG Document Scanner (upload & chunk inspection)
  6. Agentic Tool Guardrails (Pillar IV SSRF and AST analysis)
  7. Malware Binary Analysis (Pillar I heuristics, MalConv, MalImg)
  8. Code Security & AST Scanner (Pillar II CWE detector)
  9. Adversarial Audit (Pillar V TAP-Lite red-team campaign manager)
  10. Vision & Document Threat Scanner (Pillar III image/PDF/DOCX tester)
  [VERIFIED sentinel/dashboard/app.py:304-315].

---

## 6. Discrepancies (Docs vs Code)
1. **SRM Filter Bank Count**:
   - `docs/pillar-3-plan/03_srm_filter_and_steganography.md:15-30` refers to a "30-filter Spatial Rich Model filter bank" [STORED RESULT sentinel/docs/pillar-3-plan/03_srm_filter_and_steganography.md:15-30].
   - Code reality: `sentinel/core/vision/srm/kernels.py:12-18, 150-186` implements **10 Spatial Rich Model residual kernels** padded to 5x5 and stacked to a tensor of shape `(10, 1, 5, 5)` [VERIFIED sentinel/core/vision/srm/kernels.py:12-18, 153].
2. **Audio Deepfake Detection**:
   - `br1_plan/05_Voice_Attack_Surface.md:1-70` refers to voice attack surfaces.
   - Code reality: Audio deepfake classification is NOT implemented; `voice_client.py` implements client-side speech-to-text transcription via Whisper for testing gateway prompt injection defenses [VERIFIED sentinel/core/security_vectors/voice_client.py:1-50].
