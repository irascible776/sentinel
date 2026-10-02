# Module 4: Security Operations Web Dashboard
**Developer 3 (Utkarsh) | Branch: `br1` | File: `dashboard/app.py`**

---

## 1. Objective
Build the real-time visual command center used to demonstrate the AI Security Gateway during DTU faculty evaluations and final vivas. The dashboard displays live analytics, telemetry metrics, multi-agent decision inspector, and a high-visibility canary exfiltration banner.

---

## 2. Technical Specification

### 2.1 File Location
`dashboard/app.py`

### 2.2 Framework & Port
* **Framework:** Streamlit (Python)
* **Port:** `8501` (`http://127.0.0.1:8501`)
* **Data Sources:** Polling Gateway REST APIs (`http://127.0.0.1:8000/api/v1/*`) with fallback to local SQLite queries if the gateway is offline.

---

## 3. UI Layout & Visual Components

```
┌────────────────────────────────────────────────────────────────────────┐
│               AI SECURITY GATEWAY — OPERATIONS DASHBOARD               │
├────────────────────────────────────────────────────────────────────────┤
│ [🚨 CRITICAL ALERT BANNER: CANARY EXFILTRATION DETECTED (Flashes Red)] │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ Total Prompts     │ Attacks Blocked   │ Flagged Prompts │ Avg Latency  │
│ 1,420             │ 68 (4.8%)         │ 112 (7.9%)      │ 24.2 ms      │
├───────────────────┴───────────────────┴────────────────────────────────┤
│ 📊 TAB 1: Live Attack Telemetry (Real-time tabular feed with scores)   │
│ 🧠 TAB 2: Multi-Agent Debate Inspector (Pattern vs Semantic vs Behav)  │
│ 🛡️ TAB 3: Honeypot & Canary Alerts (Confirmed leaks & exfiltration)   │
│ ⚡ TAB 4: Threat Intelligence Feed (View & trigger auto-learned rules) │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Component Details
1. **Executive Metrics Row:**
   * Total Requests Analyzed
   * Attacks Blocked (HTTP 403)
   * Flagged Prompts (High priority warnings)
   * Canary Exfiltration Breaches
   * Average Gateway Overhead Latency
2. **Canary Alert Flash Banner:**
   * Renders at the very top using `st.error()` whenever `/api/v1/canary-alerts` returns records.
   * Displays the leaked canary token, snippet, timestamp, and action taken (`STREAM_TERMINATED`).
3. **Multi-Agent Verdict Inspector:**
   * Select any prompt to see how Rohit's 4 agents scored it:
     * Pattern Hunter: Progress bar $0\text{--}100$
     * Semantic Analyst: Progress bar $0\text{--}100$
     * Behavioral Profiler: Progress bar $0\text{--}100$
     * Judge Agent: Composite Risk & Natural Language Reasoning
4. **Threat Feed Trigger Button:**
   * A button labelled **"Run Threat Intelligence Clustering Now"** that calls `POST /api/v1/threat-intel/run` and displays new regex rules.

---

## 4. Run & Test Command
```bash
streamlit run dashboard/app.py --server.port 8501
```
