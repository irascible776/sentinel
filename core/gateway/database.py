import json
import uuid
from datetime import datetime
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
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=True)
    decision = Column(String(16), nullable=False, index=True) # 'ALLOW', 'FLAG', 'BLOCK'
    risk_score = Column(Float, nullable=False)
    latency_ms = Column(Float, nullable=False)
    agent_breakdown = Column(Text, nullable=False) # Store JSON string
    reasoning = Column(Text, nullable=False)
    is_stream = Column(Boolean, default=False)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(64), primary_key=True, default=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    request_id = Column(String(64), nullable=True)
    session_id = Column(String(64), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    event_type = Column(String(32), nullable=False, index=True) # 'PROMPT_INJECTION', 'CANARY_EXFILTRATION', 'PII_LEAK'
    severity = Column(String(16), nullable=False) # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    details = Column(Text, nullable=False) # Store JSON string

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def log_request(session_id: str, prompt: str, response: str, decision: str, risk_score: float, latency_ms: float, agent_breakdown: dict, reasoning: str, is_stream: bool = False) -> str:
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
