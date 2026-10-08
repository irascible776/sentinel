# AI Security Gateway — Project Progress & Cross-Module Linkage Specification
**DTU B.Tech Minor Project (IT401) | Group 138 | Department of Information Technology, DTU**  
**Supervisor:** Dr. Akshay Mool | **Branch:** `br1`

---

## 1. Executive Status Dashboard

| Developer | Assigned Role | Target Directory | Implementation Status | Test Coverage |
|---|---|---|:---:|:---:|
| **Dev 1 — Rohit** | ML & Detection Brain | `core/detection/` | 🟡 **Baseline Skeleton Operational** | Heuristic `JudgeAgent` & `threat_rules.json` active |
| **Dev 2 — Rupesh** | Gateway Proxy & Server | `core/gateway/` | ⚪ **Ready for Wiring** | Full API & DB contracts specified; awaiting proxy logic |
| **Dev 3 — Utkarsh** | Security Vectors, UI & Extension | `core/security_vectors/`<br>`dashboard/`<br>`extension/` | 🟢 **100% COMPLETE** | **12 / 12 Pytest Suites Passing (100%)** |

---

## 2. What Is Done (Developer 3 — Utkarsh Scope)

Developer 3 (Utkarsh) has completed all 6 core deliverables, test fixtures, and automated testbeds:

### 2.1 Completed Modules & Deliverables

```
[ DEVELOPER 3: COMPLETED WORKSPACE ]
├── core/security_vectors/
│   ├── canary.py           ✅ Add-on 2: Honeypot Canary Engine (generation, injection, leak detection)
│   ├── rag_scanner.py      ✅ Add-on 11: RAG Poisoning Scanner (sliding chunker, PDF/TXT, Judge hook)
│   ├── threat_feed.py      ✅ Add-on 12: Threat Intelligence Feed (TF-IDF clustering, AUTO-SIGs)
│   └── voice_client.py     ✅ Add-on 9: Voice Attack Surface Client (Whisper pipeline, mic/wav capture)
├── dashboard/
│   └── app.py              ✅ Core UI: Streamlit Security Operations Center (5 live tabs, canary banner)
├── extension/
│   ├── manifest.json       ✅ Add-on 10: Chrome Extension Manifest V3 configuration
│   ├── background.js       ✅ Add-on 10: CSP-immune background service worker (fetch relay)
│   ├── content.js          ✅ Add-on 10: DOM prompt interceptor on ChatGPT/Claude with modal warning
│   ├── popup.html          ✅ Add-on 10: Dark-theme status popup interface (pure vanilla CSS)
│   └── popup.js            ✅ Add-on 10: Gateway status polling and stats display
├── tests/
│   ├── test_security_vectors.py ✅ 12 comprehensive unit tests (Canary, RAG, ThreatFeed, Voice)
│   └── samples/
│       ├── audio/adversarial_sample.wav ✅ 16kHz synthetic test tone for offline voice evaluation
│       └── rag_docs/doc_clean_1.txt & doc_poisoned.txt ✅ Real university knowledge fixtures
```

### 2.2 Verification & Test Results
- **Automated Unit Tests:** `12 passed in 5.26s` via `pytest tests/test_security_vectors.py -v`.
- **Syntax / Compilation:** 100% passing across all Python files (`py_compile`), JavaScript files (`node -c`), and JSON files.
- **Dependency Installation:** `streamlit`, `soundfile`, `sounddevice`, `pytest`, `pytest-asyncio`, `aiofiles` installed.

---

## 3. How to Link Dev 3's Modules to Other Developers (Dev 1 & Dev 2)

All interfaces are designed for seamless, zero-friction integration. Below is the exact code required by Developer 2 (Rupesh) and Developer 1 (Rohit) to consume Utkarsh's work.

---

### 🔗 Linkage 1: Dev 2 (Rupesh) $\longleftrightarrow$ Canary Honeypot Engine

**Utkarsh's Module:** [`core/security_vectors/canary.py`](file:///home/utkarsh/Desktop/minor/core/security_vectors/canary.py)

#### Where & How Dev 2 Wires It In:
1. **In `core/gateway/proxy.py` (Before Forwarding to Upstream LLM):**
   ```python
   from core.security_vectors.canary import CanaryEngine

   canary_engine = CanaryEngine()

   # After JudgeAgent evaluates and returns ALLOW:
   # Inject secret token into the system prompt:
   instrumented_messages, canary_token = canary_engine.inject_into_prompt(
       messages=request.messages, 
       session_id=session_id
   )
   # Forward instrumented_messages to upstream LLM (OpenAI / Ollama / Mock)
   ```

2. **In `core/gateway/stream_interceptor.py` (Inside SSE Streaming Sliding Window):**
   ```python
   # Inside the server-sent events generator loop:
   window_buffer += new_chunk_text

   if canary_engine.check_leak(window_buffer, canary_token):
       # 1. Immediately terminate upstream SSE connection
       # 2. Log breach event to SQLite security_events table:
       db.execute(
           "INSERT INTO security_events (id, session_id, event_type, severity, details) "
           "VALUES (?, ?, 'CANARY_EXFILTRATION', 'CRITICAL', ?)",
           (str(uuid.uuid4()), session_id, json.dumps({"token": canary_token, "snippet": window_buffer}))
       )
       # 3. Yield circuit breaker error chunk to client:
       yield "data: [ERROR: CONNECTION TERMINATED DUE TO CANARY EXFILTRATION]\n\n"
       break
   ```

3. **In `core/gateway/dlp.py` (Full Non-Streaming Response Scanner):**
   ```python
   if canary_engine.check_leak(response_text, canary_token):
       # Redact response and return HTTP 403
       return {"error": "Exfiltration blocked", "code": "CANARY_BREACH"}
   ```

---

### 🔗 Linkage 2: Dev 2 (Rupesh) $\longleftrightarrow$ Threat Intelligence Feed

**Utkarsh's Module:** [`core/security_vectors/threat_feed.py`](file:///home/utkarsh/Desktop/minor/core/security_vectors/threat_feed.py)

#### Where & How Dev 2 Wires It In:
In `core/gateway/app.py` (or router):
```python
from fastapi import FastAPI
from core.security_vectors.threat_feed import ThreatIntelligenceFeed

app = FastAPI()
threat_feed = ThreatIntelligenceFeed(
    db_path="gateway.db", 
    rules_path="core/detection/threat_rules.json"
)

@app.post("/api/v1/threat-intel/run")
async def trigger_threat_intelligence():
    """
    Called by Utkarsh's Dashboard button to run clustering on blocked prompts
    and synthesize new signatures into threat_rules.json.
    """
    result = threat_feed.run_clustering_and_update(lookback_limit=100)
    return result
```

#### Shared Database Contract (Reading Rupesh's Table):
`threat_feed.py` reads directly from the `requests` table:
```sql
SELECT prompt FROM requests 
WHERE decision = 'BLOCK' 
ORDER BY timestamp DESC 
LIMIT 100;
```

---

### 🔗 Linkage 3: Dev 2 (Rupesh) $\longleftrightarrow$ Security Operations Dashboard & Chrome Extension

**Utkarsh's Deliverables:** [`dashboard/app.py`](file:///home/utkarsh/Desktop/minor/dashboard/app.py) & [`extension/`](file:///home/utkarsh/Desktop/minor/extension/)

#### Endpoints Dev 2's FastAPI Gateway Must Expose on Port 8000:

| HTTP Method | Route | Consumed By | Purpose & Contract |
|---|---|---|---|
| `GET` | `/health` | Dashboard | Status badge: `{"status": "ok", "uptime_sec": 120}` |
| `GET` | `/api/v1/stats` | Dashboard & Extension Popup | Executive counters: `{"total_prompts": int, "allowed_count": int, "flagged_count": int, "blocked_count": int, "avg_latency_ms": float}` |
| `GET` | `/api/v1/events` | Dashboard Live Feed | Array of request objects: `[{"id": "...", "timestamp": "...", "session_id": "...", "prompt": "...", "decision": "...", "risk_score": 0.0, "matched_signatures": [], "reasoning": "..."}]` |
| `GET` | `/api/v1/canary-alerts` | Dashboard Canary Banner | Array of leaks: `[{"id": "...", "session_id": "...", "canary_token": "...", "timestamp": "...", "action_taken": "..."}]` |
| `GET` | `/api/v1/rules` | Dashboard Rules Tab | Array of signatures from `threat_rules.json`: `[{"id": "SIG-001", "name": "...", "pattern": "...", "severity": "...", "weight": 100}]` |
| `POST` | `/api/v1/inspect` | Chrome Extension & RAG | Preflight prompt check: Body: `{"prompt": "...", "session_id": "..."}` $\rightarrow$ Response: `{"decision": "ALLOW"|"FLAG"|"BLOCK", "risk_score": float, "reasoning": "...", "matched_signatures": []}` |
| `POST` | `/v1/chat/completions` | Voice Client & Chat Client | Standard OpenAI chat completions endpoint |

> [!TIP]
> **Resilient Offline Fallback:** Utkarsh's dashboard has built-in SQLite fallback logic. If Rupesh's FastAPI server is offline, the dashboard automatically queries `gateway.db` and `threat_rules.json` directly without crashing.

---

### 🔗 Linkage 4: Dev 1 (Rohit) $\longleftrightarrow$ RAG Scanner & Threat Feed

**Utkarsh's Deliverables:** [`core/security_vectors/rag_scanner.py`](file:///home/utkarsh/Desktop/minor/core/security_vectors/rag_scanner.py) & [`core/security_vectors/threat_feed.py`](file:///home/utkarsh/Desktop/minor/core/security_vectors/threat_feed.py)

#### How Utkarsh Calls Rohit's ML Brain:
In `rag_scanner.py`, Utkarsh imports Rohit's `JudgeAgent` directly in-process:
```python
from core.detection.judge import JudgeAgent

class RAGScanner:
    def __init__(self, judge: Optional[JudgeAgent] = None, quarantine_threshold: float = 75.0):
        self.judge = judge or JudgeAgent()
        self.quarantine_threshold = quarantine_threshold

    # When scanning retrieved document chunks:
    # eval_res = self.judge.evaluate(prompt=chunk, session_id="rag-session")
```
When Rohit upgrades `JudgeAgent` with his fine-tuned DeBERTa model (`core/detection/semantic_analyst.py`), **`rag_scanner.py` instantly inherits the advanced ML classification with zero code changes required!**

#### How Utkarsh Updates Rohit's Rules Store:
1. `ThreatIntelligenceFeed` extracts new attack n-grams and appends versioned rules into [`core/detection/threat_rules.json`](file:///home/utkarsh/Desktop/minor/core/detection/threat_rules.json).
2. Rohit's `JudgeAgent.evaluate()` checks `os.path.getmtime(self.threat_rules_path)`. When mtime changes, rules are auto-reloaded in real time on the **very next request** without restarting the application.

---

## 4. Shared SQLite Database Contract (`gateway.db`)

Rupesh creates this database on FastAPI startup (`core/gateway/database.py`). Utkarsh reads from it:

```sql
-- Utkarsh reads prompt WHERE decision='BLOCK' for ThreatFeed clustering
CREATE TABLE IF NOT EXISTS requests (
    id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    prompt TEXT NOT NULL,
    response TEXT NULL,
    decision VARCHAR(16) NOT NULL,       -- 'ALLOW', 'FLAG', 'BLOCK'
    risk_score FLOAT NOT NULL,
    latency_ms FLOAT NOT NULL,
    agent_breakdown JSON NOT NULL,       -- {"pattern_hunter_score": 90.0, ...}
    reasoning TEXT NOT NULL,
    is_stream BOOLEAN DEFAULT FALSE
);

-- Utkarsh reads WHERE event_type='CANARY_EXFILTRATION' for Dashboard Canary Banner
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) REFERENCES requests(id),
    session_id VARCHAR(64) NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(32) NOT NULL,     -- 'CANARY_EXFILTRATION', 'PROMPT_INJECTION'
    severity VARCHAR(16) NOT NULL,       -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    details JSON NOT NULL
);
```

---

## 5. End-to-End System Smoke-Test Commands

As Dev 1 and Dev 2 bring their modules online, run these commands to verify complete system cohesion:

```bash
# 1. Run Dev 3 Unit Tests (Standalone verification)
python3 -m pytest tests/test_security_vectors.py -v

# 2. Start Gateway API (When Rupesh completes core/gateway/app.py)
uvicorn core.gateway.app:app --host 127.0.0.1 --port 8000 --reload

# 3. Start Security Dashboard (Utkarsh)
streamlit run dashboard/app.py --server.port 8501

# 4. Trigger Voice Client against Gateway
python3 core/security_vectors/voice_client.py --file tests/samples/audio/adversarial_sample.wav

# 5. Load Chrome Extension in Browser
# Chrome -> chrome://extensions/ -> Load unpacked -> select /home/utkarsh/Desktop/minor/extension/
```
