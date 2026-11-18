# Sentinel Codebase Inventory & Coverage Audit

## 1. Directory Tree (3 Levels)
```
sentinel
├── AGENTS.md
├── AI_Security_Gateway_Features.md
├── ARCHITECTURE.md
├── Sentinel v2.0 - Scope Expansion Spec.md
├── Sentinel_Scope_Expansion_Roadmap.pdf
├── br1_plan
│   ├── 01_Canary_Engine.md
│   ├── 02_RAG_Poisoning_Scanner.md
│   ├── 03_Threat_Intelligence_Feed.md
│   ├── 04_Security_Dashboard.md
│   ├── 05_Voice_Attack_Surface.md
│   ├── 06_Chrome_Extension.md
│   ├── 07_Testing_and_Viva_Demo.md
│   └── README.md
├── br2_plan
│   ├── 01_Pattern_Hunter.md
│   ├── 02_Semantic_Analyst.md
│   ├── 03_Behavioral_Profiler.md
│   ├── 04_Judge_Agent_Consensus.md
│   ├── 05_Threat_Rules_Contract.md
│   ├── 06_Benchmarking_and_Evaluation.md
│   ├── 07_Testing_and_Viva_Demo.md
│   └── README.md
├── br3_plan
│   └── rupesh_implementation_plan.md
├── core
│   ├── __init__.py
│   ├── codesec
│   │   ├── __init__.py
│   │   ├── ast_parser.py
│   │   ├── codebert_head.py
│   │   ├── config.py
│   │   ├── engine.py
│   │   ├── judge.py
│   │   ├── schemas.py
│   │   └── secret_scanner.py
│   ├── detection
│   │   ├── __init__.py
│   │   ├── behavioral_profiler.py
│   │   ├── guardrails
│   │   ├── intent_classifier.py
│   │   ├── judge.py
│   │   ├── normalizer.py
│   │   ├── pattern_hunter.py
│   │   ├── semantic_analyst.py
│   │   ├── stage2_arbiter.py
│   │   ├── threat_rules.json
│   │   └── tool_guardrail.py
│   ├── gateway
│   │   ├── __init__.py
│   │   ├── app.py
│   │   ├── ast_analyzer.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── dlp.py
│   │   ├── proxy.py
│   │   ├── static
│   │   └── stream_interceptor.py
│   ├── malware
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── engine.py
│   │   ├── entropy.py
│   │   ├── heuristics.py
│   │   ├── judge.py
│   │   ├── malconv.py
│   │   ├── malimg.py
│   │   ├── preprocess.py
│   │   ├── schemas.py
│   │   └── weights
│   ├── redteam
│   │   ├── __init__.py
│   │   ├── data
│   │   ├── hardening.py
│   │   ├── judge.py
│   │   ├── mutators
│   │   ├── runner.py
│   │   ├── schemas.py
│   │   └── search.py
│   │   └── targets.py
│   ├── security_vectors
│   │   ├── __init__.py
│   │   ├── canary.py
│   │   ├── rag_scanner.py
│   │   ├── threat_feed.py
│   │   └── voice_client.py
│   └── vision
│       ├── __init__.py
│       ├── config.py
│       ├── consensus
│       ├── document
│       ├── engine.py
│       ├── ocr
│       ├── preprocessing
│       ├── redaction
│       ├── schemas.py
│       ├── semantic
│       └── srm
├── dashboard
│   └── app.py
├── docs
│   ├── Instructions for Students - B Tech project mid sem eval.pdf
│   ├── minor project ppt.pdf
│   ├── pillar-3-plan
│   │   ├── 01_model_selection_and_semantic_vision.md
│   │   ├── 02_ocr_and_visual_prompt_injection.md
│   │   ├── 03_srm_filter_and_steganography.md
│   │   ├── 04_document_threat_parser.md
│   │   ├── 05_consensus_judge_and_redaction.md
│   │   ├── 06_api_and_dashboard_integration.md
│   │   └── README.md
│   ├── pillar-5-plan
│   │   ├── 01_model_selection_and_training.md
│   │   ├── 02_multi_turn_attack_algorithms.md
│   │   ├── 03_judge_and_scoring_mechanisms.md
│   │   ├── 04_closed_loop_auto_immunization.md
│   │   ├── 05_target_integration_and_api.md
│   │   ├── 06_consensus_log.md
│   │   └── README.md
│   └── study_guides
│       ├── README.md
│       ├── pillar_1_malware_analysis.md
│       ├── pillar_2_code_security.md
│       └── pillar_4_agentic_guardrails.md
├── extension
│   ├── background.js
│   ├── content.js
│   ├── manifest.json
│   ├── popup.html
│   └── popup.js
├── gateway.db
├── gateway.db-shm
├── gateway.db-wal
├── models
│   ├── arbiter_gguf
│   │   └── Llama-3.2-1B-Instruct-Q4_K_M.gguf
│   ├── redteam_gguf
│   │   └── gemma-2-2b-it-Q4_K_M.gguf
│   └── sentinel_deberta
│       ├── added_tokens.json
│       ├── calibration.json
│       ├── config.json
│       ├── model.safetensors
│       ├── special_tokens_map.json
│       ├── spm.model
│       ├── tokenizer.json
│       └── tokenizer_config.json
├── notebooks
│   ├── sentinel_colab_training.ipynb
│   └── train_colab.py
├── plans
│   ├── Developer_1_Rohit_ML_Detection_Guide.md
│   ├── Developer_2_Rupesh_Gateway_Systems_Guide.md
│   ├── Developer_3_Utkarsh_Security_Vectors_UI_Guide.md
│   ├── System_Integration_and_Linkage_Specification.md
│   ├── progress.md
│   └── reference.md
├── pytest.ini
├── requirements.txt
├── research_papers
├── run.py
├── scratch
├── scripts
│   ├── download_models.py
│   ├── download_pillar5_model.py
│   └── verify_all_pillars.py
├── sentinel
├── sentinel_model
│   ├── chat_template.jinja
│   ├── config.json
│   ├── model.safetensors
│   ├── sentinel_pillar4_model.zip
│   ├── tokenizer.json
│   └── tokenizer_config.json
├── start.py
├── stop.py
├── stop.sh
└── tests
    ├── benchmark_detection.py
    ├── benchmark_expanded.py
    ├── benchmark_full_662.py
    ├── demo_chat_client.html
    ├── samples
    ├── test_code_security.py
    ├── test_components.py
    ├── test_detection.py
    ├── test_gateway.py
    ├── test_malware_scanner.py
    ├── test_redteam.py
    ├── test_security_vectors.py
    ├── test_tool_guardrail.py
    └── test_vision.py
```

## 2. Git Stats
- **Total Commit Count**: 16 [VERIFIED command: `cd sentinel && git rev-list --count HEAD` -> `16`]
- **First Commit Date**: `2026-09-29 15:10:31 +0530` [VERIFIED command: `cd sentinel && git log --reverse --format="%ad %h %s" --date=iso | head -n 1` -> `2026-09-29 15:10:31 +0530 08f5c0e Initialize project directory structure for Group 138`]
- **Latest Commit Date**: `2026-11-02 16:40:15 +0530` [VERIFIED command: `cd sentinel && git log -n 1 --format="%ad %h %s" --date=iso` -> `2026-11-02 16:40:15 +0530 b197b3d feat: complete Sentinel v2.0 AI Security Gateway (Pillars I-V)`]
- **Active Branch**: `main` [VERIFIED command: `cd sentinel && git branch --show-current` -> `main`]
- **Remote Origin**: `git@github.com:irascible776/sentinel.git` [VERIFIED command: `cd sentinel && git remote -v`]

## 3. Dependencies & Exact Versions

### From `sentinel/requirements.txt` [VERIFIED sentinel/requirements.txt:1-41]
- `fastapi>=0.110.0`
- `uvicorn[standard]>=0.28.0`
- `pydantic>=2.6.0`
- `pydantic-settings>=2.2.0`
- `sqlalchemy>=2.0.0`
- `httpx>=0.27.0`
- `aiofiles>=23.2.1`
- `python-dotenv>=1.0.1`
- `transformers>=4.38.0`
- `torch>=2.2.0`
- `scikit-learn>=1.4.0`
- `sentencepiece>=0.2.0`
- `huggingface_hub>=0.21.0`
- `llama-cpp-python>=0.2.56`
- `streamlit>=1.32.0`
- `requests>=2.31.0`
- `soundfile>=0.12.1`
- `scipy>=1.12.0`
- `sounddevice>=0.4.6`
- `pillow>=10.2.0`
- `pymupdf>=1.24.0`
- `python-docx>=1.1.0`
- `pytest>=8.0.0`
- `pytest-asyncio>=0.23.0`

### Active Environment (`python3 -m pip freeze`) [VERIFIED command output]
- `aiofiles==25.1.0`
- `fastapi==0.141.1`
- `huggingface_hub==1.32.0`
- `httpx==0.28.1`
- `httpx-sse==0.4.3`
- `numpy==2.5.3`
- `onnxruntime==1.30.0`
- `pillow==10.2.0`
- `pydantic==2.13.5`
- `pydantic-settings==2.15.0`
- `pymupdf==1.28.2`
- `pypdf==6.19.0`
- `pytest==9.1.1`
- `pytest-asyncio==1.4.0`
- `python-docx==1.2.0`
- `python-dotenv==1.2.3`
- `requests==2.34.2`
- `safetensors==0.8.0`
- `scikit-learn==1.9.1`
- `scipy==1.18.1`
- `sentence-transformers==6.1.0`
- `sounddevice==0.5.6`
- `soundfile==0.14.0`
- `SQLAlchemy==2.0.54`
- `starlette==1.6.0`
- `streamlit==1.65.0`
- `tokenizers==0.23.2`
- `torch==2.14.0+cpu`
- `transformers==5.17.0`
- `uvicorn==0.53.0`
- `uvloop==0.22.1`
- `websockets==15.0.1`

## 4. Test Collection Summary
Command: `cd sentinel && python3 -m pytest --collect-only -q`
Total collected tests: **171** [VERIFIED command output]
- `tests/test_code_security.py`: 30 tests
- `tests/test_components.py`: 2 tests
- `tests/test_detection.py`: 25 tests
- `tests/test_gateway.py`: 11 tests
- `tests/test_malware_scanner.py`: 13 tests
- `tests/test_redteam.py`: 28 tests
- `tests/test_security_vectors.py`: 12 tests
- `tests/test_tool_guardrail.py`: 21 tests
- `tests/test_vision.py`: 29 tests

## 5. Source File Coverage Checklist

| File Path | LOC | Fully Read | Notes / Status |
| :--- | :--- | :--- | :--- |
| `sentinel/core/__init__.py` | 0 | Yes | Package marker |
| `sentinel/core/codesec/__init__.py` | 23 | Yes | Pillar II exports |
| `sentinel/core/codesec/ast_parser.py` | 481 | Yes | AST & Lexical code security engine |
| `sentinel/core/codesec/codebert_head.py` | 218 | Yes | CodeBERT classification head |
| `sentinel/core/codesec/config.py` | 61 | Yes | Thresholds and model configurations |
| `sentinel/core/codesec/engine.py` | 198 | Yes | Unified code security pipeline orchestrator |
| `sentinel/core/codesec/judge.py` | 177 | Yes | 3-tier precedence judge for code security |
| `sentinel/core/codesec/schemas.py` | 88 | Yes | Pydantic data models for code scans |
| `sentinel/core/codesec/secret_scanner.py` | 272 | Yes | Regex & Shannon entropy secret detector |
| `sentinel/core/detection/__init__.py` | 0 | Yes | Package marker |
| `sentinel/core/detection/behavioral_profiler.py` | 172 | Yes | Sliding window session risk calculator |
| `sentinel/core/detection/guardrails/__init__.py` | 3 | Yes | Guardrail package marker |
| `sentinel/core/detection/guardrails/ast_normalizer.py` | 145 | Yes | Tool call shell/SQL AST validator |
| `sentinel/core/detection/guardrails/ssrf_filter.py` | 190 | Yes | SSRF IP and DNS resolution defense |
| `sentinel/core/detection/intent_classifier.py` | 306 | Yes | Stage 1 heuristic / semantic intent routing |
| `sentinel/core/detection/judge.py` | 312 | Yes | Multi-agent fusion judge |
| `sentinel/core/detection/normalizer.py` | 82 | Yes | Unicode, leetspeak, and slang normalizer |
| `sentinel/core/detection/pattern_hunter.py` | 158 | Yes | Regex pattern matcher for prompt injection |
| `sentinel/core/detection/semantic_analyst.py` | 152 | Yes | DeBERTa-v3 ONNX/PyTorch classifier |
| `sentinel/core/detection/stage2_arbiter.py` | 407 | Yes | Llama-3.2 / Gemini Stage-2 deep arbiter |
| `sentinel/core/detection/threat_rules.json` | 150 | Yes | PatternHunter regex signature dictionary |
| `sentinel/core/detection/tool_guardrail.py` | 303 | Yes | Pillar IV tool execution inspection |
| `sentinel/core/gateway/__init__.py` | 0 | Yes | Package marker |
| `sentinel/core/gateway/app.py` | 886 | Yes | FastAPI core application and HTTP routing |
| `sentinel/core/gateway/ast_analyzer.py` | 221 | Yes | Egress code execution safety filter |
| `sentinel/core/gateway/config.py` | 46 | Yes | Gateway environment and port configurations |
| `sentinel/core/gateway/database.py` | 251 | Yes | SQLite WAL audit logging and metrics persistence |
| `sentinel/core/gateway/dlp.py` | 54 | Yes | PII and API secret regex redactor |
| `sentinel/core/gateway/proxy.py` | 120 | Yes | Async reverse proxy client to upstream LLMs |
| `sentinel/core/gateway/stream_interceptor.py` | 128 | Yes | SSE response stream scanner & circuit breaker |
| `sentinel/core/malware/__init__.py` | 6 | Yes | Pillar I exports |
| `sentinel/core/malware/config.py` | 82 | Yes | Malware scanner thresholds and paths |
| `sentinel/core/malware/engine.py` | 207 | Yes | Pillar I malware scanner engine |
| `sentinel/core/malware/entropy.py` | 81 | Yes | Shannon sliding entropy and packing detector |
| `sentinel/core/malware/heuristics.py` | 275 | Yes | PE/ELF/Mach-O static header & section rules |
| `sentinel/core/malware/judge.py` | 171 | Yes | Malware ensemble consensus arbiter |
| `sentinel/core/malware/malconv.py` | 84 | Yes | 1D CNN raw-byte malware classifier |
| `sentinel/core/malware/malimg.py` | 137 | Yes | 2D ResNet/CNN byte-to-image texture classifier |
| `sentinel/core/malware/preprocess.py` | 81 | Yes | Byte parsing and fixed-size tensor normalizer |
| `sentinel/core/malware/schemas.py` | 82 | Yes | Malware detection request/response Pydantic models |
| `sentinel/core/redteam/__init__.py` | 6 | Yes | Pillar V exports |
| `sentinel/core/redteam/hardening.py` | 240 | Yes | Closed-loop rule generator and immunization |
| `sentinel/core/redteam/judge.py` | 192 | Yes | Red-team multi-tier evaluator |
| `sentinel/core/redteam/mutators/__init__.py` | 5 | Yes | Mutators export marker |
| `sentinel/core/redteam/mutators/strategist.py` | 147 | Yes | LLM-directed attack prompt mutator |
| `sentinel/core/redteam/mutators/syntactic.py` | 146 | Yes | Rule-based syntactic obfuscators |
| `sentinel/core/redteam/runner.py` | 225 | Yes | Async red-team squad campaign runner |
| `sentinel/core/redteam/schemas.py` | 116 | Yes | Pydantic data schemas for red-team runs |
| `sentinel/core/redteam/search.py` | 290 | Yes | Tree of Attacks with Pruning (TAP-Lite) search |
| `sentinel/core/redteam/targets.py` | 374 | Yes | Multi-target adapters (Local, OpenAI, Anthropic) |
| `sentinel/core/security_vectors/__init__.py` | 0 | Yes | Package marker |
| `sentinel/core/security_vectors/canary.py` | 54 | Yes | Honeytoken generator and leak detector |
| `sentinel/core/security_vectors/rag_scanner.py` | 138 | Yes | Sliding window indirect injection detector |
| `sentinel/core/security_vectors/threat_feed.py` | 185 | Yes | TF-IDF n-gram clusterer & signature generator |
| `sentinel/core/security_vectors/voice_client.py` | 152 | Yes | Audio capture and Whisper speech-to-text bridge |
| `sentinel/core/vision/__init__.py` | 25 | Yes | Pillar III exports |
| `sentinel/core/vision/config.py` | 68 | Yes | Vision threat detection configuration |
| `sentinel/core/vision/consensus/calibration.py` | 81 | Yes | Zero-FP Platt scaling / calibration |
| `sentinel/core/vision/consensus/judge.py` | 167 | Yes | Vision multi-channel consensus judge |
| `sentinel/core/vision/document/docx_parser.py` | 121 | Yes | DOCX XML font and opacity threat extractor |
| `sentinel/core/vision/document/hidden_text_rules.py` | 172 | Yes | Structural oracles for microscopic text |
| `sentinel/core/vision/document/page_aggregator.py` | 84 | Yes | Multipage document threat aggregator |
| `sentinel/core/vision/document/pdf_parser.py` | 177 | Yes | PyMuPDF text & drawing layer extractor |
| `sentinel/core/vision/engine.py` | 357 | Yes | Vision & Document Threat Pipeline orchestrator |
| `sentinel/core/vision/ocr/base.py` | 36 | Yes | Abstract base class for OCR engines |
| `sentinel/core/vision/ocr/easyocr_driver.py` | 84 | Yes | EasyOCR hardware driver |
| `sentinel/core/vision/ocr/factory.py` | 78 | Yes | Lazy-loading driver factory with mock fallback |
| `sentinel/core/vision/ocr/mock_driver.py` | 119 | Yes | Deterministic mock OCR driver for CI/testing |
| `sentinel/core/vision/ocr/tesseract_driver.py` | 75 | Yes | PyTesseract driver |
| `sentinel/core/vision/preprocessing/image_prep.py` | 152 | Yes | EXIF strip, RGB conversion, aspect ratio resize |
| `sentinel/core/vision/preprocessing/text_presence.py` | 98 | Yes | Otsu binarization & edge density gate |
| `sentinel/core/vision/redaction/redactor.py` | 94 | Yes | Bounding box pixel masker & redactor |
| `sentinel/core/vision/schemas.py` | 162 | Yes | Pydantic models for vision threat analysis |
| `sentinel/core/vision/semantic/concept_bank.py` | 160 | Yes | Visual prompt injection concept embeddings |
| `sentinel/core/vision/semantic/concept_scorer.py` | 115 | Yes | Cosine similarity scoring against threat concepts |
| `sentinel/core/vision/semantic/mobileclip_encoder.py` | 135 | Yes | MobileCLIP / OpenCLIP feature extractor |
| `sentinel/core/vision/srm/kernels.py` | 186 | Yes | Steganographic 30 Spatial Rich Model filter bank |
| `sentinel/core/vision/srm/lsb_detector.py` | 109 | Yes | Chi-square LSB steganography analyzer |
| `sentinel/core/vision/srm/pgd_detector.py` | 138 | Yes | High-frequency adversarial perturbation detector |
| `sentinel/dashboard/app.py` | 1376 | Yes | Streamlit SOC Telemetry Dashboard |
| `sentinel/extension/background.js` | 48 | Yes | Chrome extension background service worker |
| `sentinel/extension/content.js` | 151 | Yes | Chrome extension DOM interceptor & UI injector |
| `sentinel/extension/manifest.json` | 34 | Yes | Chrome extension Manifest V3 definition |
| `sentinel/extension/popup.html` | 116 | Yes | Chrome extension UI popup |
| `sentinel/extension/popup.js` | 37 | Yes | Chrome extension settings toggle handler |
| `sentinel/scripts/download_models.py` | 283 | Yes | Model weights downloader script |
| `sentinel/scripts/download_pillar5_model.py` | 46 | Yes | Pillar 5 redteam GGUF downloader |
| `sentinel/scripts/verify_all_pillars.py` | 230 | Yes | End-to-end integration verification suite |
| `sentinel/run.py` | 132 | Yes | Unified process runner (FastAPI + Streamlit) |
| `sentinel/start.py` | 115 | Yes | Background daemon launcher |
| `sentinel/stop.py` | 331 | Yes | Process termination and cleanup utility |
| `sentinel/stop.sh` | 35 | Yes | Shell script process killer |
| `sentinel/tests/benchmark_detection.py` | 110 | Yes | Detection pipeline latency benchmark |
| `sentinel/tests/benchmark_expanded.py` | 188 | Yes | Expanded dataset benchmark runner |
| `sentinel/tests/benchmark_full_662.py` | 175 | Yes | Full 662 deepset benchmark runner |
| `sentinel/tests/test_code_security.py` | 521 | Yes | Pillar II code security unit tests (30 tests) |
| `sentinel/tests/test_components.py` | 28 | Yes | DLP & Stream interceptor unit tests (2 tests) |
| `sentinel/tests/test_detection.py` | 396 | Yes | Ingress detection unit tests (25 tests) |
| `sentinel/tests/test_gateway.py` | 175 | Yes | FastAPI gateway route unit tests (11 tests) |
| `sentinel/tests/test_malware_scanner.py` | 212 | Yes | Pillar I malware scanner unit tests (13 tests) |
| `sentinel/tests/test_redteam.py` | 391 | Yes | Pillar V redteam squad unit tests (28 tests) |
| `sentinel/tests/test_security_vectors.py` | 210 | Yes | Canary, RAG, ThreatFeed tests (12 tests) |
| `sentinel/tests/test_tool_guardrail.py` | 169 | Yes | Pillar IV tool guardrail tests (21 tests) |
| `sentinel/tests/test_vision.py` | 492 | Yes | Pillar III vision engine tests (29 tests) |
