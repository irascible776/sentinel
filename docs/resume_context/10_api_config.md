# 10 API Specifications, CLI Tools & Configuration Registry

This document catalogs every HTTP route, CLI script, environment variable, and configuration threshold in Sentinel.

---

## 1. HTTP Endpoints Catalog (`sentinel/core/gateway/app.py`)

| HTTP Method | Path | Authentication / Headers | Request Payload Schema | Response Schema | Evidence (File:Line) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | None | None | HTML file `static/index.html` (Web Chat GUI) | [VERIFIED sentinel/core/gateway/app.py:77-88] |
| `GET` | `/demo` | None | None | HTML file `static/index.html` | [VERIFIED sentinel/core/gateway/app.py:78] |
| `GET` | `/sentinel` | None | None | HTML file `static/index.html` | [VERIFIED sentinel/core/gateway/app.py:79] |
| `GET` | `/health` | None | None | `{"status": "ok", "service": str, "version": str, "uptime_seconds": float, "active_rules": int, "engine_ready": bool}` | [VERIFIED sentinel/core/gateway/app.py:92-99] |
| `POST` | `/v1/chat/completions` | None (Optional session headers: `x-session-id`, cookie: `sentinel_sid`) | Standard OpenAI schema: `{"messages": [{"role": str, "content": str \| list}], "model": str, "stream": bool, "session_id"?: str}` | If clean: Chat completion JSON with `security_metadata: {...}`; If streaming: SSE stream; If blocked: HTTP 403 `{"error": {"code": "PROMPT_INJECTION_BLOCKED", "risk_score": float, ...}}` | [VERIFIED sentinel/core/gateway/app.py:101-325] |
| `POST` | `/api/v1/inspect` | None | `{"prompt": str, "session_id"?: str}` | `{"prompt": str, "decision": "ALLOW" \| "FLAG" \| "BLOCK", "risk_score": float, "confidence": float, "latency_ms": float, "agent_breakdown": {...}, "matched_signatures": [...], "reasoning": str, "request_id": str}` | [VERIFIED sentinel/core/gateway/app.py:327-367] |
| `POST` | `/api/v1/inspect-tool` | None | `{"tool_name": str, "arguments": dict, "session_id"?: str}` | `{"decision": "ALLOW" \| "BLOCK", "risk_score": float, "is_suspicious": bool, "policy_action": str, "matched_rules": [...], "ast_details": {...}, "ssrf_details": {...}, "model_score": float, "latency_ms": float, "reasoning": str}` | [VERIFIED sentinel/core/gateway/app.py:369-402] |
| `POST` | `/api/v1/scan-file` | None | Multipart form upload: `file: UploadFile` (binary up to 32 MB) | `MalwareScanResult` schema: `{"verdict": "BENIGN" \| "SUSPICIOUS" \| "MALICIOUS", "risk_score": float, "heuristics": {...}, "malconv": {...}, "malimg": {...}, "entropy": {...}, "sha256": str, "file_size": int, "latency_ms": float, "reasoning": str}` | [VERIFIED sentinel/core/gateway/app.py:404-459] |
| `POST` | `/api/v1/scan-code` | None | `CodeScanRequest`: `{"code": str, "language": str, "source": str}` | `CodeScanResult`: `{"verdict": "CLEAN" \| "SUSPICIOUS" \| "MALICIOUS", "policy_action": "ALLOW" \| "QUARANTINE" \| "BLOCK", "composite_risk": float, "confidence": float, "findings": [...], "ast_analysis": {...}, "codebert_analysis": {...}, "secret_analysis": {...}, "latency_ms": float, "reasoning": str}` | [VERIFIED sentinel/core/gateway/app.py:462-512] |
| `POST` | `/api/v1/scan-image` | None | Multipart form upload: `file: UploadFile` (PNG/JPEG/WebP) | `VisionScanResult`: `{"verdict": "CLEAN" \| "SUSPICIOUS" \| "VISUAL_INJECTION", "policy_action": "ALLOW" \| "FLAG" \| "BLOCK" \| "REDACT_IMAGE", "composite_risk_score": float, "confidence": float, "ocr_analysis": {...}, "concept_analysis": {...}, "srm_analysis": {...}, "stego_analysis": {...}, "redacted_image_base64"?: str, "matched_signatures": [...], "reasoning": str}` | [VERIFIED sentinel/core/gateway/app.py:515-582] |
| `POST` | `/api/v1/scan-document` | None | Multipart form upload: `file: UploadFile` (PDF or DOCX) | `DocScanResult`: `{"verdict": str, "policy_action": str, "composite_risk_score": float, "page_count": int, "hidden_text_findings": [...], "high_risk_pages": [...], "extracted_text_sample": str, "latency_ms": float, "reasoning": str}` | [VERIFIED sentinel/core/gateway/app.py:585-649] |
| `GET` | `/api/v1/stats` | None | Query params: None | `{"total_requests": int, "blocked_requests": int, "flagged_requests": int, "allowed_requests": int, "block_rate_pct": float, "avg_latency_ms": float, "system_uptime_seconds": float, "active_rules_count": int}` | [VERIFIED sentinel/core/gateway/app.py:652-676] |
| `GET` | `/api/v1/events` | None | Query params: `limit: int = 50, offset: int = 0` | List of request log records: `[{"id": str, "timestamp": str, "session_id": str, "prompt": str, "response": str, "decision": str, "risk_score": float, "latency_ms": float, "agent_breakdown": {...}, "matched_signatures": [...], "reasoning": str}, ...]` | [VERIFIED sentinel/core/gateway/app.py:679-714] |
| `GET` | `/api/v1/canary-alerts` | None | Query params: `limit: int = 50, offset: int = 0` | List of security alert records: `[{"id": str, "timestamp": str, "session_id": str, "event_type": str, "severity": str, "details": {...}, "request_id": str}, ...]` | [VERIFIED sentinel/core/gateway/app.py:717-746] |
| `GET` | `/api/v1/rules` | None | Query params: None | Raw JSON rule dictionary from `core/detection/threat_rules.json`: `{"version": str, "updated_at": str, "rules": [...]}` | [VERIFIED sentinel/core/gateway/app.py:749-755] |
| `POST` | `/api/v1/threat-intel/run` | None | None | `{"status": "ok", "new_signatures_generated": int, "signatures": [...], "timestamp": str}` | [VERIFIED sentinel/core/gateway/app.py:758-774] |
| `POST` | `/api/v1/redteam/audit/start` | Header `X-RedTeam-Service-Key` matching `REDTEAM_SERVICE_KEY` | `RedTeamStartRequest`: `{"target_type": str, "target_endpoint": str, "target_model"?: str, "seed_probes"?: list, "categories"?: list, "beam_width"?: int, "max_depth"?: int}` | `{"campaign_id": str, "status": "STARTED", "message": str}` | [VERIFIED sentinel/core/gateway/app.py:777-823] |
| `GET` | `/api/v1/redteam/audit/status/{campaign_id}` | Header `X-RedTeam-Service-Key` matching `REDTEAM_SERVICE_KEY` | None | `{"campaign_id": str, "status": str, "progress_pct": float, "nodes_evaluated": int, "vulnerabilities_found": int}` | [VERIFIED sentinel/core/gateway/app.py:826-832] |
| `GET` | `/api/v1/redteam/audit/report/{campaign_id}` | Header `X-RedTeam-Service-Key` matching `REDTEAM_SERVICE_KEY` | None | `RedTeamCampaignReport` schema containing execution timeline, branch lineage tree, and immunization suggestions | [VERIFIED sentinel/core/gateway/app.py:835-869] |
| `POST` | `/api/v1/redteam/rules/promote/{rule_id}` | Header `X-RedTeam-Service-Key` matching `REDTEAM_SERVICE_KEY` | None | `{"status": "ok", "message": "Rule promoted to ACTIVE enforcement", "rule_id": str}` | [VERIFIED sentinel/core/gateway/app.py:872-885] |

---

## 2. CLI Entry Points & Scripts

1. **`sentinel/run.py`**:
   - Unified process runner. Checks socket port availability on `:8000` and `:8501`. Spawns Uvicorn (`core.gateway.app:app` on port 8000) and Streamlit (`dashboard/app.py` on port 8501) as child processes with clean SIGINT/SIGTERM handlers releasing ports on exit [VERIFIED sentinel/run.py:21-125].
2. **`sentinel/start.py`**:
   - Background daemon runner. Spawns `run.py` in the background and redirects logs to `.sentinel.log` [VERIFIED sentinel/start.py:20-110].
3. **`sentinel/stop.py` & `sentinel/stop.sh`**:
   - Process termination scripts. Discovers running Sentinel PIDs on ports 8000 and 8501 and terminates them gracefully via SIGTERM, falling back to SIGKILL [VERIFIED sentinel/stop.py:30-320; sentinel/stop.sh:1-35].
4. **`sentinel/scripts/download_models.py`**:
   - Model downloader utility. CLI flags: `--all`, `--channel-b`, `--arbiter`, `--arbiter-lite`, `--redteam`, `--vision`. Downloads GGUF and Hugging Face weights into `sentinel/models/` [VERIFIED sentinel/scripts/download_models.py:10-280].
5. **`sentinel/scripts/download_pillar5_model.py`**:
   - Targeted downloader for Google Gemma-2-2B-IT GGUF into `sentinel/models/redteam_gguf/` [VERIFIED sentinel/scripts/download_pillar5_model.py:1-46].
6. **`sentinel/scripts/verify_all_pillars.py`**:
   - Integration verification runner. Executes test requests against all 5 pillars and verifies response schemas and exit codes [VERIFIED sentinel/scripts/verify_all_pillars.py:1-230].
7. **`sentinel/core/security_vectors/voice_client.py`**:
   - Voice attack surface client. CLI flags: `--file <path_to_wav>` or runs live microphone recording via `sounddevice` at 16,000 Hz, transcribes via Whisper, and posts to gateway [VERIFIED sentinel/core/security_vectors/voice_client.py:9-30, 75-148].
8. **Root Wrappers (`run.py`, `start.py`, `stop.py`, `stop.sh`)**:
   - Convenience scripts in repository parent directory forwarding execution directly to `sentinel/<script>` [VERIFIED run.py:10-21].

---

## 3. Environment Variables & Configuration Keys

| Config Key | Default Value | Configured In | Purpose | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| `GATEWAY_HOST` | `"127.0.0.1"` | `sentinel/core/gateway/config.py:7` | Host interface for FastAPI ASGI server | [VERIFIED sentinel/core/gateway/config.py:7] |
| `GATEWAY_PORT` | `8000` | `sentinel/core/gateway/config.py:8` | Port for FastAPI ASGI server | [VERIFIED sentinel/core/gateway/config.py:8] |
| `GATEWAY_DEBUG` | `True` | `sentinel/core/gateway/config.py:9` | Debug logging toggle | [VERIFIED sentinel/core/gateway/config.py:9] |
| `GATEWAY_ADMIN_KEY` | `"gw-admin-secret-key-dtu138"` | `sentinel/core/gateway/config.py:10` | Administrative key | [VERIFIED sentinel/core/gateway/config.py:10] |
| `REDTEAM_SERVICE_KEY` | `None` | `sentinel/core/gateway/config.py:11` | Header authorization secret for Pillar V `/api/v1/redteam/*` endpoints | [VERIFIED sentinel/core/gateway/config.py:11] |
| `UPSTREAM_PROVIDER` | `"gemini"` | `sentinel/core/gateway/config.py:14` | Upstream provider type (`"gemini"`, `"mock"`, `"openai"`, `"ollama"`) | [VERIFIED sentinel/core/gateway/config.py:14] |
| `UPSTREAM_BASE_URL` | `"https://generativelanguage.googleapis.com/v1beta/openai"` | `sentinel/core/gateway/config.py:15` | Upstream base URL | [VERIFIED sentinel/core/gateway/config.py:15] |
| `UPSTREAM_API_KEY` | `""` | `sentinel/core/gateway/config.py:16` | Upstream API key | [VERIFIED sentinel/core/gateway/config.py:16] |
| `UPSTREAM_MODEL` | `"gemini-1.5-flash"` | `sentinel/core/gateway/config.py:17` | Upstream target model name | [VERIFIED sentinel/core/gateway/config.py:17] |
| `GEMINI_API_KEY` | `""` | `sentinel/core/gateway/config.py:20` | Dedicated Google Gemini API key | [VERIFIED sentinel/core/gateway/config.py:20] |
| `GEMINI_MODEL` | `"gemini-1.5-flash"` | `sentinel/core/gateway/config.py:21` | Google Gemini model name | [VERIFIED sentinel/core/gateway/config.py:21] |
| `GEMINI_BASE_URL` | `"https://generativelanguage.googleapis.com/v1beta/openai"` | `sentinel/core/gateway/config.py:22` | Google Gemini OpenAI-compatible base URL | [VERIFIED sentinel/core/gateway/config.py:22] |
| `HF_MODEL_NAME` | `"protectai/deberta-v3-base-prompt-injection-v2"` | `sentinel/core/gateway/config.py:25` | DeBERTa model identifier / local path | [VERIFIED sentinel/core/gateway/config.py:25] |
| `DETECTION_DEVICE` | `"auto"` | `sentinel/core/gateway/config.py:26` | PyTorch execution device (`"auto"` = MPS > CPU, `"cuda"`, `"mps"`, `"cpu"`) | [VERIFIED sentinel/core/gateway/config.py:26] |
| `SLIDING_WINDOW_MINUTES`| `10` | `sentinel/core/gateway/config.py:27` | Behavioral profiler temporal window | [VERIFIED sentinel/core/gateway/config.py:27] |
| `THREAT_RULES_PATH` | `"core/detection/threat_rules.json"` | `sentinel/core/gateway/config.py:28` | Path to PatternHunter regex dictionary | [VERIFIED sentinel/core/gateway/config.py:28] |
| `ARBITER_GGUF_PATH` | `""` | `sentinel/core/gateway/config.py:31` | Local path to Stage 2 GGUF model file | [VERIFIED sentinel/core/gateway/config.py:31] |
| `ARBITER_BACKEND` | `"auto"` | `sentinel/core/gateway/config.py:32` | Arbiter backend priority (`"auto"`, `"local"`, `"groq"`, `"gemini"`) | [VERIFIED sentinel/core/gateway/config.py:32] |
| `GROQ_API_KEY` | `""` | `sentinel/core/gateway/config.py:33` | Optional Groq API key for Llama Guard 3 | [VERIFIED sentinel/core/gateway/config.py:33] |
| `INTENT_MODEL_PATH` | `""` | `sentinel/core/gateway/config.py:36` | Optional secondary harm transformer path | [VERIFIED sentinel/core/gateway/config.py:36] |
| `CANARY_TOKEN_PREFIX` | `"CANARY-SECRET-"` | `sentinel/core/gateway/config.py:39` | Prefix for generated honeytokens | [VERIFIED sentinel/core/gateway/config.py:39] |
| `DATABASE_URL` | `"sqlite:///./gateway.db"` | `sentinel/core/gateway/config.py:40` | SQLAlchemy database connection string | [VERIFIED sentinel/core/gateway/config.py:40] |
| `DASHBOARD_PORT` | `8501` | `sentinel/core/gateway/config.py:41` | Streamlit SOC Dashboard network port | [VERIFIED sentinel/core/gateway/config.py:41] |
| `AUDIO_SAMPLE_RATE` | `16000` | `sentinel/core/gateway/config.py:42` | Whisper audio sampling frequency (Hz) | [VERIFIED sentinel/core/gateway/config.py:42] |
| `VISION_OCR_BACKEND` | `"auto"` | `sentinel/core/vision/config.py:21` | OCR driver override (`"auto"`, `"easyocr"`, `"tesseract"`, `"mock"`) | [VERIFIED sentinel/core/vision/config.py:21] |
| `VISION_DEVICE` | `"auto"` | `sentinel/core/vision/config.py:12` | Vision device override (`"auto"`, `"mps"`, `"cuda"`, `"cpu"`) | [VERIFIED sentinel/core/vision/config.py:12] |
| `VISION_ALLOW_REDACTION`| `True` | `sentinel/core/vision/config.py:58` | Solid mask redaction toggle | [VERIFIED sentinel/core/vision/config.py:58] |
