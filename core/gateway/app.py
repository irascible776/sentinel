import asyncio
import os
import json
import time
import uuid
import httpx
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from core.detection.judge import JudgeAgent
from core.security_vectors.canary import CanaryEngine
# Try to import ThreatIntelligenceFeed if it exists
try:
    from core.security_vectors.threat_feed import ThreatIntelligenceFeed
except ImportError:
    ThreatIntelligenceFeed = None

from core.detection.tool_guardrail import tool_guardrail
from core.malware.engine import malware_engine
from core.codesec.engine import code_security_engine
from core.codesec.schemas import CodeScanRequest
from core.vision.engine import vision_engine
from core.vision.schemas import VisionScanResult, DocScanResult, VisionPolicyActionEnum, VisionVerdictEnum

from core.gateway.config import settings
from core.gateway.database import init_db, log_request
from core.gateway.proxy import forward_to_upstream
from core.gateway.dlp import dlp_scanner
from core.gateway.stream_interceptor import stream_interceptor

SERVER_START_TIME = time.time()
judge = JudgeAgent()
canary_engine = CanaryEngine(prefix=settings.CANARY_TOKEN_PREFIX)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB schema
    init_db()
    # Initialize global async HTTP client
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
    # Warmup detection engine (pre-loads DeBERTa model weights, tokenizer, and JIT into RAM)
    try:
        await asyncio.to_thread(judge.evaluate, "Warmup Sentinel gateway initialization", "sess-warmup")
    except Exception:
        pass
    yield
    # Cleanup on shutdown
    await app.state.http_client.aclose()

app = FastAPI(title="AI Security Gateway", version="1.0.0", lifespan=lifespan)

# Essential for Dashboard and Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR   = os.path.join(os.path.dirname(__file__), "static")
STATIC_INDEX = os.path.join(STATIC_DIR, "index.html")

# ── Serve static sub-directories (CSS / JS / images etc.) ──────────────────
# Must be mounted BEFORE the FileResponse route so Starlette route order
# doesn't shadow the static mounts (static mounts are matched first by path).
_css_dir = os.path.join(STATIC_DIR, "css")
_js_dir  = os.path.join(STATIC_DIR, "js")
if os.path.isdir(_css_dir):
    app.mount("/css", StaticFiles(directory=_css_dir), name="static-css")
if os.path.isdir(_js_dir):
    app.mount("/js",  StaticFiles(directory=_js_dir),  name="static-js")

@app.get("/")
@app.get("/demo")
@app.get("/sentinel")
async def serve_demo_gui():
    if os.path.exists(STATIC_INDEX):
        return FileResponse(
            STATIC_INDEX,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
    return HTMLResponse("<h2>AI Security Gateway is running. Interactive GUI not found.</h2>")

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "uptime_sec": round(time.time() - SERVER_START_TIME, 2),
        "timestamp": time.time(),
        "service": "AI Security Gateway"
    }

@app.post("/v1/chat/completions")
async def chat_completions(request: Request, background_tasks: BackgroundTasks):
    t_start = time.perf_counter()
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Session Resolution: payload -> header -> cookie -> ephemeral UUID
    session_id = (
        payload.get("session_id")
        or request.headers.get("x-session-id")
        or request.cookies.get("sentinel_sid")
        or f"sess-{uuid.uuid4().hex[:12]}"
    )
    messages = payload.get("messages", [])
    stream = payload.get("stream", False)
    
    # Extract latest user prompt and multimodal image blocks across message history
    user_text_parts = []
    image_bytes_to_scan = []
    for msg in messages:
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                user_text_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        if part.get("type") == "text":
                            user_text_parts.append(part.get("text", ""))
                        elif part.get("type") == "image_url":
                            url_obj = part.get("image_url", {})
                            url_str = url_obj.get("url", "") if isinstance(url_obj, dict) else str(url_obj)
                            if url_str.startswith("data:image/") and ";base64," in url_str:
                                import base64
                                b64_data = url_str.split(";base64,")[1]
                                try:
                                    image_bytes_to_scan.append(base64.b64decode(b64_data))
                                except Exception:
                                    pass
                            elif url_str.startswith(("http://", "https://")):
                                return JSONResponse(status_code=400, content={
                                    "error": {
                                        "code": "REMOTE_IMAGE_URL_UNSUPPORTED",
                                        "message": "Direct remote HTTP/HTTPS image URLs are prohibited under perimeter anti-SSRF/TOCTOU policy. Submit image as inline base64 data URI."
                                    }
                                })
    user_text = " ".join(user_text_parts).strip()
            
    # Step 0.5: Multimodal Image Inspection (Pillar III)
    if image_bytes_to_scan:
        for img_b in image_bytes_to_scan:
            img_res = await asyncio.to_thread(vision_engine.scan_image, img_b, "multimodal_upload.png")
            if img_res.policy_action == VisionPolicyActionEnum.BLOCK:
                request_id = f"req-{uuid.uuid4().hex[:12]}"
                latency_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
                background_tasks.add_task(
                    log_request,
                    session_id=session_id,
                    prompt=f"MULTIMODAL_IMAGE_BLOCKED (sha256:{img_res.sha256[:12]}...): {user_text[:60]}",
                    response="",
                    decision="BLOCK",
                    risk_score=img_res.composite_risk_score,
                    latency_ms=latency_ms,
                    agent_breakdown={"vision_risk": img_res.composite_risk_score, "format": img_res.format},
                    reasoning=f"Blocked by Pillar III Vision Engine: {img_res.reasoning}",
                    is_stream=stream,
                    matched_signatures=list(img_res.matched_signatures)
                )
                return JSONResponse(status_code=403, content={
                    "error": {
                        "code": "MULTIMODAL_THREAT_BLOCKED",
                        "message": "Visual threat rejected by AI Security Gateway (Pillar III)",
                        "decision": "BLOCK",
                        "risk_score": img_res.composite_risk_score,
                        "reasoning": img_res.reasoning,
                        "matched_signatures": img_res.matched_signatures,
                        "request_id": request_id
                    }
                })
            elif img_res.ocr_analysis.raw_text:
                # Merge clean OCR text into prompt for comprehensive text arbitration
                user_text = f"{user_text}\n[IMAGE_OCR_TEXT]: {img_res.ocr_analysis.raw_text}".strip()

    if not user_text and not image_bytes_to_scan:
        raise HTTPException(status_code=400, detail="No user message found")

    # Step 1: Ingress Security Check (Async Non-Blocking Execution with Timeout)
    try:
        verdict = await asyncio.wait_for(
            asyncio.to_thread(judge.evaluate, prompt=user_text, session_id=session_id),
            timeout=10.0
        )
    except asyncio.TimeoutError:
        fast_scan = judge.pattern_hunter.scan(user_text)
        verdict = {
            "decision": "BLOCK",
            "risk_score": 85.0,
            "confidence": 0.5,
            "agent_breakdown": {
                "pattern_hunter_score": fast_scan.get("score", 0.0),
                "semantic_analyst_score": None,
                "behavioral_profiler_score": 0.0,
                "stage2_arbiter_score": None,
                "stage2_invoked": False,
            },
            "matched_signatures": fast_scan.get("matched_signatures", []),
            "reasoning": "Perimeter security timeout: Request failed verification within SLA budget (Fail-Secure Policy Enforced)."
        }
    except Exception as e:
        fast_scan = judge.pattern_hunter.scan(user_text)
        verdict = {
            "decision": "BLOCK",
            "risk_score": 85.0,
            "confidence": 0.5,
            "agent_breakdown": {
                "pattern_hunter_score": fast_scan.get("score", 0.0),
                "semantic_analyst_score": None,
                "behavioral_profiler_score": 0.0,
                "stage2_arbiter_score": None,
                "stage2_invoked": False,
            },
            "matched_signatures": fast_scan.get("matched_signatures", []),
            "reasoning": f"Detection engine encountered error ({str(e)}). Request blocked under fail-secure policy."
        }
    
    request_id = f"req-{uuid.uuid4().hex[:12]}"
    latency_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
    matched_sigs = verdict.get("matched_signatures", [])
    
    if verdict["decision"] == "BLOCK":
        # Log the blocked request
        background_tasks.add_task(
            log_request,
            session_id=session_id,
            prompt=user_text,
            response="",
            decision="BLOCK",
            risk_score=verdict.get("risk_score", 100.0),
            latency_ms=latency_ms,
            agent_breakdown=verdict.get("agent_breakdown", {}),
            reasoning=verdict.get("reasoning", "Blocked by engine"),
            is_stream=stream,
            matched_signatures=matched_sigs
        )
        return JSONResponse(status_code=403, content={
            "error": {
                "code": "PROMPT_INJECTION_BLOCKED",
                "message": "Request rejected by AI Security Gateway",
                "decision": "BLOCK",
                "risk_score": verdict.get("risk_score"),
                "reasoning": verdict.get("reasoning"),
                "agent_breakdown": verdict.get("agent_breakdown"),
                "matched_signatures": matched_sigs,
                "request_id": request_id
            }
        })
        
    # Step 2: Inject Canary
    instrumented_messages, canary_token = canary_engine.inject_into_prompt(messages, session_id)
    payload["messages"] = instrumented_messages
    
    # Step 3: Forward to Upstream
    client = getattr(app.state, "http_client", None)
    temp_client = None
    if client is None:
        temp_client = httpx.AsyncClient(timeout=30.0)
        client = temp_client

    try:
        upstream_response = await forward_to_upstream(client, payload, stream=stream)
    except Exception as e:
        if temp_client:
            await temp_client.aclose()
        raise HTTPException(status_code=502, detail=f"Upstream provider error: {str(e)}")
    
    if stream:
        # Step 4a: Streaming Circuit Breaker
        return StreamingResponse(
            stream_interceptor(upstream_response, canary_token, session_id, request_id),
            media_type="text/event-stream"
        )
    else:
        # Step 4b: Response Guard DLP
        # Extract full response text
        content = ""
        if "choices" in upstream_response and len(upstream_response["choices"]) > 0:
            content = upstream_response["choices"][0]["message"].get("content", "")
            
        redacted_content = dlp_scanner.scan(content, canary_token, session_id, request_id)
        
        # Replace content with redacted version
        if "choices" in upstream_response and len(upstream_response["choices"]) > 0:
            upstream_response["choices"][0]["message"]["content"] = redacted_content
            
        decision_val = verdict.get("decision", "ALLOW")
        status_val = "VERIFIED_SAFE" if decision_val == "ALLOW" else "FLAGGED_MONITORED"

        # Append security metadata
        upstream_response["security_metadata"] = {
            "status": status_val,
            "decision": decision_val,
            "risk_score": verdict.get("risk_score", 0.0),
            "confidence": verdict.get("confidence", 1.0),
            "latency_ms": latency_ms,
            "agent_breakdown": verdict.get("agent_breakdown", {})
        }
        
        # Log request with actual decision
        background_tasks.add_task(
            log_request,
            session_id=session_id,
            prompt=user_text,
            response=redacted_content,
            decision=decision_val,
            risk_score=verdict.get("risk_score", 0.0),
            latency_ms=latency_ms,
            agent_breakdown=verdict.get("agent_breakdown", {}),
            reasoning=verdict.get("reasoning", "Clean"),
            is_stream=False,
            matched_signatures=matched_sigs
        )
        
        return upstream_response

@app.post("/api/v1/inspect")
async def inspect_prompt(request: Request):
    payload = await request.json()
    prompt = payload.get("prompt", "")
    session_id = payload.get("session_id", "default")
    messages = payload.get("messages", [])

    # Authenticated Trust Boundary:
    # If X-Sentinel-Audit header is presented, it MUST be accompanied by a valid Bearer token.
    audit_header = request.headers.get("X-Sentinel-Audit")
    if audit_header is not None:
        expected_key = getattr(settings, "REDTEAM_SERVICE_KEY", None)
        if not expected_key:
            raise HTTPException(
                status_code=503,
                detail="Audit functionality unavailable: REDTEAM_SERVICE_KEY is not configured on server."
            )
        auth_header = request.headers.get("Authorization", "")
        if auth_header != f"Bearer {expected_key}":
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: X-Sentinel-Audit header requires valid Bearer credential."
            )
        is_audit = True
    else:
        is_audit = False

    # If prompt not explicitly given, extract latest user turn from messages
    if not prompt and messages:
        for msg in reversed(messages):
            if msg.get("role") == "user":
                prompt = msg.get("content", "")
                break
    
    verdict = judge.evaluate(
        prompt=prompt,
        session_id=session_id,
        messages=messages if is_audit else None,
        is_audit=is_audit
    )
    return verdict

@app.post("/api/v1/inspect-tool")
async def inspect_tool(request: Request, background_tasks: BackgroundTasks):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    tool_name = payload.get("tool_name", "")
    arguments = payload.get("arguments", "")
    session_id = payload.get("session_id", f"agent-{uuid.uuid4().hex[:8]}")

    if not tool_name:
        raise HTTPException(status_code=400, detail="Missing required field 'tool_name'")

    result = tool_guardrail.inspect_tool_call(tool_name=tool_name, arguments=arguments)

    matched_sigs = [result["flagged_by"]] if result.get("decision") == "BLOCK" else []
    background_tasks.add_task(
        log_request,
        session_id=session_id,
        prompt=f"TOOL_CALL: {tool_name}({arguments})",
        response=json.dumps(result),
        decision=result.get("decision", "ALLOW"),
        risk_score=result.get("risk_score", 0.0),
        latency_ms=result.get("latency_ms", 0.0),
        agent_breakdown={"guardrail": result.get("flagged_by", "CLEAN")},
        reasoning=result.get("reason", "Clean"),
        is_stream=False,
        matched_signatures=matched_sigs
    )

    if result.get("decision") == "BLOCK":
        return JSONResponse(status_code=403, content=result)
    return JSONResponse(status_code=200, content=result)

@app.post("/api/v1/scan-file")
async def scan_file(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    session_id: str = "binary-scan"
):
    # Enforce streaming chunked read with hard 32MB cap
    max_bytes = 32 * 1024 * 1024
    chunks = []
    total_bytes = 0
    
    try:
        while True:
            chunk = await file.read(64 * 1024)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise HTTPException(status_code=413, detail="File exceeds maximum allowed size of 32MB.")
            chunks.append(chunk)
    finally:
        await file.close()
        
    data = b"".join(chunks)
    
    # Run malware inspection engine
    result = malware_engine.scan_bytes(data=data, filename=file.filename or "sample.bin")
    result_dict = result.model_dump()
    
    # Audit logging to SQLite WAL
    matched_sigs = [f"MALWARE:{result.family_attribution.primary_family}"] if result.verdict == "MALICIOUS" else []
    if result.heuristics.anomaly_flags:
        matched_sigs.extend(result.heuristics.anomaly_flags)
        
    db_decision = "BLOCK" if result.policy_action == "BLOCK" else ("FLAG" if result.policy_action in ("QUARANTINE", "ALERT") else "ALLOW")
    
    background_tasks.add_task(
        log_request,
        session_id=session_id,
        prompt=f"BINARY_SCAN: {file.filename} (sha256:{result.sha256[:12]}..., size:{total_bytes} bytes)",
        response=json.dumps(result_dict),
        decision=db_decision,
        risk_score=result.composite_risk_score,
        latency_ms=result.scan_latency_ms,
        agent_breakdown={
            "format": result.heuristics.detected_format,
            "heuristics_flags": len(result.heuristics.anomaly_flags),
            "malconv_score": result.engine_scores.get("malconv").risk_score if "malconv" in result.engine_scores else 0.0,
            "malimg_family": result.family_attribution.primary_family
        },
        reasoning=result.reasoning,
        is_stream=False,
        matched_signatures=matched_sigs
    )
    
    status_code = 403 if result.policy_action == "BLOCK" else (400 if result.verdict == "NOT_EXECUTABLE" else 200)
    return JSONResponse(status_code=status_code, content=result_dict)

@app.post("/api/v1/scan-code")
def scan_code(
    payload: CodeScanRequest,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    session_id: str = "code-scan"
):
    """
    Pillar II: Code Security & AST Vulnerability Detection Endpoint.
    Analyzes code snippets or files for SQLi (CWE-89), Command Injection (CWE-78),
    Insecure Deserialization (CWE-502), and Hard-coded Credentials (CWE-798).
    """
    if not payload.code or not payload.code.strip():
        raise HTTPException(status_code=400, detail="Code payload cannot be empty.")

    result = code_security_engine.scan_code(
        code=payload.code,
        language=payload.language or "python",
        filename=payload.filename or "snippet.py",
        options=payload.options
    )
    result_dict = result.model_dump()

    # Audit logging to SQLite WAL
    matched_sigs = [f"CODE:{f.cwe}" for f in result.findings]
    if result.secrets:
        matched_sigs.extend([f"SECRET:{s.kind}" for s in result.secrets])

    db_decision = "BLOCK" if result.policy_action == "BLOCK" else ("FLAG" if result.policy_action in ("QUARANTINE", "ALERT") else "ALLOW")

    background_tasks.add_task(
        log_request,
        session_id=session_id,
        prompt=f"CODE_SCAN: {payload.filename} (sha256:{result.sha256[:12]}..., lang:{result.language}, lines:{result.total_lines})",
        response=json.dumps(result_dict),
        decision=db_decision,
        risk_score=result.composite_risk_score,
        latency_ms=result.scan_latency_ms,
        agent_breakdown={
            "language": result.language,
            "parser_backend": result.ast_report.parser_backend,
            "findings_count": len(result.findings),
            "secrets_count": len(result.secrets),
            "codebert_risk": result.codebert_score.risk_score,
            "cached": result.cached
        },
        reasoning=result.reasoning,
        is_stream=False,
        matched_signatures=matched_sigs
    )

    status_code = 403 if result.policy_action == "BLOCK" else (400 if result.verdict == "UNSCANNABLE" else 200)
    return JSONResponse(status_code=status_code, content=result_dict)

@app.post("/api/v1/scan-image")
async def scan_image(
    file: UploadFile = File(...),
    redact: bool = False,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    session_id: str = "image-scan"
):
    """
    Pillar III: Vision Threat Detection Endpoint.
    Analyzes images for prompt injections, zero-text semantic jailbreaks,
    adversarial noise (PGD/FGSM), and LSB steganography.
    """
    max_bytes = 32 * 1024 * 1024
    chunks = []
    total_bytes = 0

    try:
        while True:
            chunk = await file.read(64 * 1024)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise HTTPException(status_code=413, detail="Image exceeds maximum allowed size of 32MB.")
            chunks.append(chunk)
    finally:
        await file.close()

    data = b"".join(chunks)

    # Run Vision Engine
    result = vision_engine.scan_image(
        image_bytes=data,
        filename=file.filename or "sample.png",
        allow_redaction=redact
    )
    result_dict = result.model_dump()

    matched_sigs = list(result.matched_signatures)

    db_decision = "BLOCK" if result.policy_action == VisionPolicyActionEnum.BLOCK else (
        "FLAG" if result.policy_action in (VisionPolicyActionEnum.FLAG, VisionPolicyActionEnum.REDACT_IMAGE) else "ALLOW"
    )

    background_tasks.add_task(
        log_request,
        session_id=session_id,
        prompt=f"VISION_SCAN: {file.filename} (sha256:{result.sha256[:12]}..., size:{total_bytes} bytes)",
        response=json.dumps(result_dict),
        decision=db_decision,
        risk_score=result.composite_risk_score,
        latency_ms=result.scan_latency_ms,
        agent_breakdown={
            "ocr_risk": result.ocr_analysis.risk_score,
            "concept_risk": result.concept_analysis.risk_score,
            "noise_risk": result.noise_analysis.risk_score,
            "stego_risk": result.stego_analysis.risk_score,
            "format": result.format,
            "cached": result.cached
        },
        reasoning=result.reasoning,
        is_stream=False,
        matched_signatures=matched_sigs
    )

    status_code = 403 if result.policy_action == VisionPolicyActionEnum.BLOCK else (
        400 if result.verdict == VisionVerdictEnum.CORRUPT_UNSCANNABLE else 200
    )
    return JSONResponse(status_code=status_code, content=result_dict)

@app.post("/api/v1/scan-document")
async def scan_document(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    session_id: str = "document-scan"
):
    """
    Pillar III: Document Threat Detection Endpoint.
    Analyzes PDF and DOCX files for hidden-text prompt injections,
    microscopic fonts, render-mode 3 invisibility, and embedded image threats.
    """
    max_bytes = 32 * 1024 * 1024
    chunks = []
    total_bytes = 0

    try:
        while True:
            chunk = await file.read(64 * 1024)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise HTTPException(status_code=413, detail="Document exceeds maximum allowed size of 32MB.")
            chunks.append(chunk)
    finally:
        await file.close()

    data = b"".join(chunks)

    # Run Document Parser & Aggregator
    result = vision_engine.scan_document(
        doc_bytes=data,
        filename=file.filename or "sample.pdf"
    )
    result_dict = result.model_dump()

    matched_sigs = list(result.matched_signatures)

    db_decision = "BLOCK" if result.policy_action == VisionPolicyActionEnum.BLOCK else (
        "FLAG" if result.policy_action == VisionPolicyActionEnum.FLAG else "ALLOW"
    )

    background_tasks.add_task(
        log_request,
        session_id=session_id,
        prompt=f"DOC_SCAN: {file.filename} (sha256:{result.sha256[:12]}..., pages:{result.total_pages}, size:{total_bytes} bytes)",
        response=json.dumps(result_dict),
        decision=db_decision,
        risk_score=result.composite_risk_score,
        latency_ms=result.scan_latency_ms,
        agent_breakdown={
            "format": result.format,
            "pages": result.total_pages,
            "findings_count": len(result.findings),
            "cached": result.cached
        },
        reasoning=result.reasoning,
        is_stream=False,
        matched_signatures=matched_sigs
    )

    status_code = 403 if result.policy_action == VisionPolicyActionEnum.BLOCK else (
        400 if result.verdict == VisionVerdictEnum.CORRUPT_UNSCANNABLE else 200
    )
    return JSONResponse(status_code=status_code, content=result_dict)

# --- Telemetry Endpoints for Dashboard ---
@app.get("/api/v1/stats")
async def get_stats():
    from core.gateway.database import SessionLocal, RequestLog, SecurityEvent
    from sqlalchemy import func
    db = SessionLocal()
    try:
        total = db.query(func.count(RequestLog.id)).scalar()
        allowed = db.query(func.count(RequestLog.id)).filter(RequestLog.decision == "ALLOW").scalar()
        blocked = db.query(func.count(RequestLog.id)).filter(RequestLog.decision == "BLOCK").scalar()
        flagged = db.query(func.count(RequestLog.id)).filter(RequestLog.decision == "FLAG").scalar()
        canary_leaks = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.event_type.in_(["CANARY_EXFILTRATION", "DATA_EXFILTRATION_PREVENTED", "STREAM_CIRCUIT_BREAKER"])
        ).scalar()
        
        avg_latency = db.query(func.avg(RequestLog.latency_ms)).scalar() or 0.0
        
        return {
            "total_prompts": total or 0,
            "allowed_count": allowed or 0,
            "flagged_count": flagged or 0,
            "blocked_count": blocked or 0,
            "canary_leaks": canary_leaks or 0,
            "avg_latency_ms": round(float(avg_latency), 2)
        }
    finally:
        db.close()

@app.get("/api/v1/events")
async def get_events(limit: int = 50, offset: int = 0, verdict: str = None):
    from core.gateway.database import SessionLocal, RequestLog
    db = SessionLocal()
    try:
        query = db.query(RequestLog)
        if verdict:
            query = query.filter(RequestLog.decision == verdict)
        events = query.order_by(RequestLog.timestamp.desc()).offset(offset).limit(limit).all()
        result = []
        for e in events:
            sigs = []
            if hasattr(e, "matched_signatures") and e.matched_signatures:
                try:
                    sigs = json.loads(e.matched_signatures) if isinstance(e.matched_signatures, str) else e.matched_signatures
                except Exception:
                    sigs = [str(e.matched_signatures)]
            agent_breakdown = {}
            if e.agent_breakdown:
                try:
                    agent_breakdown = json.loads(e.agent_breakdown) if isinstance(e.agent_breakdown, str) else e.agent_breakdown
                except Exception:
                    pass
            result.append({
                "id": e.id,
                "session_id": e.session_id,
                "timestamp": e.timestamp.isoformat() if hasattr(e.timestamp, "isoformat") else str(e.timestamp),
                "prompt": e.prompt,
                "decision": e.decision,
                "risk_score": e.risk_score,
                "matched_signatures": sigs,
                "reasoning": e.reasoning,
                "agent_breakdown": agent_breakdown
            })
        return result
    finally:
        db.close()

@app.get("/api/v1/canary-alerts")
async def get_canary_alerts():
    from core.gateway.database import SessionLocal, SecurityEvent
    db = SessionLocal()
    try:
        events = db.query(SecurityEvent).filter(
            SecurityEvent.event_type.in_(["CANARY_EXFILTRATION", "DATA_EXFILTRATION_PREVENTED", "STREAM_CIRCUIT_BREAKER"])
        ).order_by(SecurityEvent.timestamp.desc()).all()
        result = []
        for e in events:
            details_dict = {}
            if e.details:
                try:
                    details_dict = json.loads(e.details) if isinstance(e.details, str) else e.details
                except Exception:
                    details_dict = {"raw": str(e.details)}
            token = details_dict.get("canary_token") or details_dict.get("token") or "CANARY-SECRET-DETECTED"
            action = details_dict.get("action_taken") or ("STREAM_TERMINATED" if e.event_type == "STREAM_CIRCUIT_BREAKER" else "RESPONSE_REDACTED")
            result.append({
                "id": e.id,
                "session_id": e.session_id,
                "timestamp": e.timestamp.isoformat() if hasattr(e.timestamp, "isoformat") else str(e.timestamp),
                "event_type": e.event_type,
                "severity": e.severity,
                "canary_token": token,
                "action_taken": action,
                "details": details_dict
            })
        return result
    finally:
        db.close()

@app.get("/api/v1/rules")
async def get_rules():
    import os
    rules_path = settings.THREAT_RULES_PATH if hasattr(settings, "THREAT_RULES_PATH") else "core/detection/threat_rules.json"
    if os.path.exists(rules_path):
        with open(rules_path, "r") as f:
            return json.load(f)
    return {"version": "0.0.0", "rules": []}

@app.post("/api/v1/threat-intel/run")
async def run_threat_intel():
    if ThreatIntelligenceFeed:
        feed = ThreatIntelligenceFeed(
            db_path=settings.DATABASE_URL.replace("sqlite:///./", "").replace("sqlite:///", "") if hasattr(settings, "DATABASE_URL") else "gateway.db",
            rules_path=settings.THREAT_RULES_PATH if hasattr(settings, "THREAT_RULES_PATH") else "core/detection/threat_rules.json"
        )
        result = feed.run_clustering_and_update()
        return result
    else:
        raise HTTPException(status_code=501, detail="Threat Intelligence Module not implemented yet")


# ── Pillar V: Automated Adversarial Robustness & Auditing Endpoints ───────────

from core.redteam.schemas import StartAuditRequest
from core.redteam.targets import is_host_allowed
from core.gateway.database import fetch_redteam_campaign, fetch_redteam_nodes

@app.post("/api/v1/redteam/audit/start", tags=["Pillar V"])
async def start_redteam_audit(req: StartAuditRequest, background_tasks: BackgroundTasks):
    """
    Launches an autonomous adversarial stress-test audit in an isolated OS subprocess.
    Protects FastAPI and guarantees 100% Metal memory reclamation.
    """
    # 1. Enforce Target Allow-List Guardrail
    if not is_host_allowed(req.target_endpoint):
        raise HTTPException(
            status_code=403,
            detail=f"Target endpoint '{req.target_endpoint}' is not in the authorized REDTEAM_ALLOWED_HOSTS list."
        )

    campaign_id = f"cmp-{uuid.uuid4().hex[:8]}"
    categories_str = ",".join([c.value for c in req.categories])

    # 2. Spawn Subprocess
    import sys
    import subprocess
    cmd = [
        sys.executable, "-m", "core.redteam.runner",
        "--campaign-id", campaign_id,
        "--target-type", req.target_type.value,
        "--target-endpoint", req.target_endpoint,
        "--target-model", req.target_model or "",
        "--categories", categories_str,
        "--max-turns", str(req.max_turns),
        "--beam-width", str(req.beam_width),
        "--branch-factor", str(req.branch_factor)
    ]
    if not req.auto_harden_shadow:
        cmd.append("--no-auto-harden")

    # Launch subprocess independently
    try:
        subprocess.Popen(cmd, close_fds=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to spawn audit runner: {e}")

    return {
        "status": "QUEUED",
        "campaign_id": campaign_id,
        "target_endpoint": req.target_endpoint,
        "target_type": req.target_type.value,
        "categories": [c.value for c in req.categories],
        "message": "Audit campaign spawned in isolated subprocess."
    }


@app.get("/api/v1/redteam/audit/status/{campaign_id}", tags=["Pillar V"])
async def get_redteam_status(campaign_id: str):
    """Polls real-time progress, depth, nodes evaluated, and breach count from SQLite WAL."""
    campaign = fetch_redteam_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@app.get("/api/v1/redteam/audit/report/{campaign_id}", tags=["Pillar V"])
async def get_redteam_report(campaign_id: str):
    """Returns complete compliance scorecard, OWASP category breakdown, and full attack tree traces."""
    campaign = fetch_redteam_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    nodes = fetch_redteam_nodes(campaign_id)
    
    # Calculate category summary
    cat_summary = {}
    for n in nodes:
        cat = n.get("category", "prompt_injection")
        if cat not in cat_summary:
            cat_summary[cat] = {"total_nodes": 0, "breaches": 0, "refusals": 0, "evasions": 0}
        cat_summary[cat]["total_nodes"] += 1
        v = n.get("verdict")
        if v == "VIOLATION_CONFIRMED":
            cat_summary[cat]["breaches"] += 1
        elif v == "REFUSED":
            cat_summary[cat]["refusals"] += 1
        elif v == "EVASIVE_NEUTRAL":
            cat_summary[cat]["evasions"] += 1

    total_seeds = max(1, campaign.get("total_seeds", 1))
    breached_seeds = campaign.get("breaches_detected", 0)
    # Resilience score: % of seeds that resisted compromise
    resilience = max(0.0, min(100.0, 100.0 * (1.0 - (breached_seeds / total_seeds))))

    return {
        "campaign": campaign,
        "nodes": nodes,
        "summary_by_category": cat_summary,
        "resilience_score": round(resilience, 1)
    }


@app.post("/api/v1/redteam/rules/promote/{rule_id}", tags=["Pillar V"])
async def promote_shadow_rule(rule_id: str):
    """Promotes a synthesized Pillar-V rule from SHADOW mode to active ENFORCE mode."""
    if not ThreatIntelligenceFeed:
        raise HTTPException(status_code=501, detail="Threat feed not loaded")
    feed = ThreatIntelligenceFeed(
        db_path=settings.DATABASE_URL.replace("sqlite:///./", "").replace("sqlite:///", "") if hasattr(settings, "DATABASE_URL") else "gateway.db",
        rules_path=settings.THREAT_RULES_PATH if hasattr(settings, "THREAT_RULES_PATH") else "core/detection/threat_rules.json"
    )
    success = feed.promote_shadow_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found or could not be promoted.")
    return {"success": True, "rule_id": rule_id, "mode": "ENFORCE"}


