import json
import uuid
import httpx
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
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

@app.post("/v1/chat/completions")
async def chat_completions(request: Request, background_tasks: BackgroundTasks):
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
    
    if verdict["decision"] == "BLOCK":
        # Log the blocked request
        background_tasks.add_task(
            log_request,
            session_id=session_id,
            prompt=user_text,
            response="",
            decision="BLOCK",
            risk_score=verdict.get("risk_score", 100.0),
            latency_ms=0.0, # Approximate
            agent_breakdown=verdict.get("agent_breakdown", {}),
            reasoning=verdict.get("reasoning", "Blocked by engine"),
            is_stream=stream
        )
        return JSONResponse(status_code=403, content={
            "error": {
                "code": "PROMPT_INJECTION_BLOCKED",
                "message": "Request rejected by AI Security Gateway",
                "decision": "BLOCK",
                "risk_score": verdict.get("risk_score"),
                "reasoning": verdict.get("reasoning"),
                "agent_breakdown": verdict.get("agent_breakdown"),
                "request_id": request_id
            }
        })
        
    # Step 2: Inject Canary
    instrumented_messages, canary_token = canary_engine.inject_into_prompt(messages, session_id)
    payload["messages"] = instrumented_messages
    
    # Step 3: Forward to Upstream
    client = app.state.http_client
    upstream_response = await forward_to_upstream(client, payload, stream=stream)
    
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
            "latency_ms": 0.0 # Approximate
        }
        
        # Log allowed request
        background_tasks.add_task(
            log_request,
            session_id=session_id,
            prompt=user_text,
            response=redacted_content,
            decision="ALLOW",
            risk_score=verdict.get("risk_score", 0.0),
            latency_ms=0.0,
            agent_breakdown=verdict.get("agent_breakdown", {}),
            reasoning=verdict.get("reasoning", "Clean"),
            is_stream=False
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
        canary_leaks = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.event_type.in_(["DATA_EXFILTRATION_PREVENTED", "STREAM_CIRCUIT_BREAKER"])).scalar()
        
        # Approximate average latency
        avg_latency = db.query(func.avg(RequestLog.latency_ms)).scalar() or 0.0
        
        return {
            "total_prompts": total,
            "allowed_count": allowed,
            "flagged_count": flagged,
            "blocked_count": blocked,
            "canary_leaks": canary_leaks,
            "avg_latency_ms": avg_latency
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
        return [
            {
                "id": e.id,
                "session_id": e.session_id,
                "timestamp": e.timestamp.isoformat(),
                "prompt": e.prompt,
                "decision": e.decision,
                "risk_score": e.risk_score,
                "reasoning": e.reasoning,
                "agent_breakdown": json.loads(e.agent_breakdown)
            } for e in events
        ]
    finally:
        db.close()

@app.get("/api/v1/canary-alerts")
async def get_canary_alerts():
    from core.gateway.database import SessionLocal, SecurityEvent
    db = SessionLocal()
    try:
        events = db.query(SecurityEvent).filter(SecurityEvent.event_type.in_(["DATA_EXFILTRATION_PREVENTED", "STREAM_CIRCUIT_BREAKER"])).order_by(SecurityEvent.timestamp.desc()).all()
        return [
            {
                "id": e.id,
                "session_id": e.session_id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "severity": e.severity,
                "details": json.loads(e.details)
            } for e in events
        ]
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
        feed = ThreatIntelligenceFeed()
        result = feed.run_clustering_and_update()
        return result
    else:
        raise HTTPException(status_code=501, detail="Threat Intelligence Module not implemented yet")
