import os
import json
import time
import uuid
import httpx
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from core.detection.judge import JudgeAgent
from core.security_vectors.canary import CanaryEngine
# Try to import ThreatIntelligenceFeed if it exists
try:
    from core.security_vectors.threat_feed import ThreatIntelligenceFeed
except ImportError:
    ThreatIntelligenceFeed = None

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

STATIC_INDEX = os.path.join(os.path.dirname(__file__), "static", "index.html")

@app.get("/")
@app.get("/demo")
async def serve_demo_gui():
    if os.path.exists(STATIC_INDEX):
        return FileResponse(STATIC_INDEX)
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

    session_id = payload.get("session_id", f"sess-{uuid.uuid4().hex[:8]}")
    messages = payload.get("messages", [])
    stream = payload.get("stream", False)
    
    # Extract latest user prompt
    user_text = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            user_text = msg.get("content", "")
            break
            
    if not user_text:
        raise HTTPException(status_code=400, detail="No user message found")

    # Step 1: Ingress Security Check (Rohit's Detection Engine)
    verdict = judge.evaluate(prompt=user_text, session_id=session_id)
    
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
    client = app.state.http_client
    try:
        upstream_response = await forward_to_upstream(client, payload, stream=stream)
    except Exception as e:
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
            
        # Append security metadata
        upstream_response["security_metadata"] = {
            "status": "VERIFIED_SAFE",
            "decision": "ALLOW",
            "risk_score": verdict.get("risk_score", 0.0),
            "confidence": verdict.get("confidence", 1.0),
            "latency_ms": latency_ms
        }
        
        # Log allowed request
        background_tasks.add_task(
            log_request,
            session_id=session_id,
            prompt=user_text,
            response=redacted_content,
            decision="ALLOW",
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
    
    verdict = judge.evaluate(prompt=prompt, session_id=session_id)
    return verdict

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

