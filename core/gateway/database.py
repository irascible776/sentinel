import json
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import create_engine, event, Column, String, Float, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

engine = create_engine("sqlite:///./gateway.db", connect_args={"check_same_thread": False})

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA busy_timeout=5000;")
    cursor.close()

Base = declarative_base()

class RequestLog(Base):
    __tablename__ = "requests"

    id = Column(String(64), primary_key=True, default=lambda: f"req-{uuid.uuid4().hex[:12]}")
    session_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=True)
    decision = Column(String(16), nullable=False, index=True) # 'ALLOW', 'FLAG', 'BLOCK'
    risk_score = Column(Float, nullable=False)
    latency_ms = Column(Float, nullable=False)
    agent_breakdown = Column(Text, nullable=False) # Store JSON string
    matched_signatures = Column(Text, nullable=True, default="[]") # Store JSON list
    reasoning = Column(Text, nullable=False)
    is_stream = Column(Boolean, default=False)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(64), primary_key=True, default=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    request_id = Column(String(64), nullable=True)
    session_id = Column(String(64), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    event_type = Column(String(32), nullable=False, index=True) # 'PROMPT_INJECTION', 'CANARY_EXFILTRATION', 'PII_LEAK'
    severity = Column(String(16), nullable=False) # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    details = Column(Text, nullable=False) # Store JSON string

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def log_request(session_id: str, prompt: str, response: str, decision: str, risk_score: float, latency_ms: float, agent_breakdown: dict, reasoning: str, is_stream: bool = False, matched_signatures: list = None) -> str:
    db = SessionLocal()
    try:
        req = RequestLog(
            session_id=session_id,
            prompt=prompt,
            response=response,
            decision=decision,
            risk_score=risk_score,
            latency_ms=latency_ms,
            agent_breakdown=json.dumps(agent_breakdown),
            matched_signatures=json.dumps(matched_signatures or []),
            reasoning=reasoning,
            is_stream=is_stream
        )
        db.add(req)
        db.commit()
        db.refresh(req)
        return req.id
    finally:
        db.close()

def log_security_event(session_id: str, event_type: str, severity: str, details: dict, request_id: str = None) -> str:
    db = SessionLocal()
    try:
        evt = SecurityEvent(
            request_id=request_id,
            session_id=session_id,
            event_type=event_type,
            severity=severity,
            details=json.dumps(details)
        )
        db.add(evt)
        db.commit()
        db.refresh(evt)
        return evt.id
    finally:
        db.close()


# ── Pillar V: Red-Team Auditing Models ────────────────────────────────────────

class RedTeamCampaign(Base):
    __tablename__ = "redteam_campaigns"

    campaign_id = Column(String(64), primary_key=True)
    target_type = Column(String(32), nullable=False)
    target_endpoint = Column(String(256), nullable=False)
    target_model = Column(String(128), nullable=True)
    status = Column(String(32), default="QUEUED", nullable=False)  # QUEUED, RUNNING, COMPLETED, FAILED, PAUSED
    total_seeds = Column(Float, default=0)
    total_nodes_evaluated = Column(Float, default=0)
    breaches_detected = Column(Float, default=0)
    rules_synthesized = Column(Float, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)


class RedTeamNode(Base):
    __tablename__ = "redteam_nodes"

    node_id = Column(String(64), primary_key=True)
    campaign_id = Column(String(64), nullable=False, index=True)
    parent_id = Column(String(64), nullable=True)
    depth = Column(Float, nullable=False)
    mutation_type = Column(String(64), nullable=False)
    prompt_text = Column(Text, nullable=False)
    response_text = Column(Text, nullable=True, default="")
    target_score = Column(Float, default=0.0)
    intent_similarity = Column(Float, default=1.0)
    verdict = Column(String(32), nullable=False)
    oracle_hit = Column(String(32), default="NONE")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


# Auto-initialize database schema on import so tables always exist
init_db()

def create_redteam_campaign(campaign_id: str, target_type: str, target_endpoint: str, target_model: str = "", total_seeds: int = 0) -> str:
    db = SessionLocal()
    try:
        cmp = RedTeamCampaign(
            campaign_id=campaign_id,
            target_type=target_type,
            target_endpoint=target_endpoint,
            target_model=target_model,
            status="RUNNING",
            total_seeds=total_seeds,
            total_nodes_evaluated=0,
            breaches_detected=0,
            rules_synthesized=0
        )
        db.add(cmp)
        db.commit()
        return cmp.campaign_id
    finally:
        db.close()


def update_redteam_campaign(campaign_id: str, status: str = None, total_nodes: int = None, breaches: int = None, rules: int = None, completed: bool = False):
    db = SessionLocal()
    try:
        cmp = db.query(RedTeamCampaign).filter(RedTeamCampaign.campaign_id == campaign_id).first()
        if cmp:
            if status:
                cmp.status = status
            if total_nodes is not None:
                cmp.total_nodes_evaluated = total_nodes
            if breaches is not None:
                cmp.breaches_detected = breaches
            if rules is not None:
                cmp.rules_synthesized = rules
            if completed:
                cmp.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def log_redteam_node(
    node_id: str,
    campaign_id: str,
    parent_id: Optional[str],
    depth: int,
    mutation_type: str,
    prompt_text: str,
    response_text: str,
    target_score: float,
    intent_similarity: float,
    verdict: str,
    oracle_hit: str = "NONE"
):
    db = SessionLocal()
    try:
        node = RedTeamNode(
            node_id=node_id,
            campaign_id=campaign_id,
            parent_id=parent_id,
            depth=depth,
            mutation_type=mutation_type,
            prompt_text=prompt_text,
            response_text=response_text,
            target_score=target_score,
            intent_similarity=intent_similarity,
            verdict=verdict,
            oracle_hit=oracle_hit
        )
        db.add(node)
        db.commit()
    finally:
        db.close()


def fetch_redteam_campaign(campaign_id: str) -> Optional[dict]:
    db = SessionLocal()
    try:
        cmp = db.query(RedTeamCampaign).filter(RedTeamCampaign.campaign_id == campaign_id).first()
        if not cmp:
            return None
        return {
            "campaign_id": cmp.campaign_id,
            "target_type": cmp.target_type,
            "target_endpoint": cmp.target_endpoint,
            "target_model": cmp.target_model,
            "status": cmp.status,
            "total_seeds": int(cmp.total_seeds or 0),
            "total_nodes_evaluated": int(cmp.total_nodes_evaluated or 0),
            "breaches_detected": int(cmp.breaches_detected or 0),
            "rules_synthesized": int(cmp.rules_synthesized or 0),
            "created_at": cmp.created_at.isoformat() if cmp.created_at else "",
            "completed_at": cmp.completed_at.isoformat() if cmp.completed_at else None
        }
    finally:
        db.close()


def fetch_redteam_nodes(campaign_id: str) -> list:
    db = SessionLocal()
    try:
        nodes = db.query(RedTeamNode).filter(RedTeamNode.campaign_id == campaign_id).order_by(RedTeamNode.created_at.asc()).all()
        return [
            {
                "node_id": n.node_id,
                "campaign_id": n.campaign_id,
                "parent_id": n.parent_id,
                "depth": int(n.depth),
                "mutation_type": n.mutation_type,
                "prompt_text": n.prompt_text,
                "response_text": n.response_text or "",
                "target_score": float(n.target_score or 0.0),
                "intent_similarity": float(n.intent_similarity or 1.0),
                "verdict": n.verdict,
                "oracle_hit": n.oracle_hit or "NONE",
                "created_at": n.created_at.isoformat() if n.created_at else ""
            }
            for n in nodes
        ]
    finally:
        db.close()


