# Developer 3 (Utkarsh) — Branch `br1` Master Scope & Execution Plan
**B.Tech Minor Project (IT401) | Group 138 | Department of IT, DTU**  
**Role:** Attack Vectors, Honeypot Traps, Threat Intelligence & Full-Stack UI/UX Engineer  
**Supervisor:** Dr. Akshay Mool  

---

## 1. Executive Summary & Our Dedicated Scope

This directory (`br1_plan/`) contains the complete technical execution blueprint for **Developer 3 (Utkarsh)** on branch `br1`. 

Our mission focuses on **advanced security capabilities, multimodal ingress vectors, deterministic honeypot traps, and the visual command center**. We build the specialized capabilities that elevate this project beyond a standard text filter into an academic-grade AI security platform.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        UTKARSH'S 6 CORE MODULES (BRANCH br1)                           │
├────┬─────────────────────────────┬─────────────────────────────────┬───────────────────┤
│ #  │ Module Name                 │ Target File Location            │ Add-on Reference  │
├────┼─────────────────────────────┼─────────────────────────────────┼───────────────────┤
│ 1  │ Canary Token Honeypot Engine│ core/security_vectors/canary.py │ Add-on 2          │
│ 2  │ RAG Poisoning Scanner       │ core/security_vectors/rag_scann.│ Add-on 11         │
│ 3  │ Threat Intelligence Feed    │ core/security_vectors/threat_fe.│ Add-on 12         │
│ 4  │ Security Operations Dashboar│ dashboard/app.py                │ Core UI           │
│ 5  │ Voice-to-Prompt Demo Client │ core/security_vectors/voice_cli.│ Add-on 9          │
│ 6  │ Chrome MV3 Browser Extension│ extension/                      │ Add-on 10         │
└────┴─────────────────────────────┴─────────────────────────────────┴───────────────────┘
```

---

## 2. Directory Navigation & Dedicated Module Guides

Each module has a dedicated step-by-step implementation guide in this folder:

1. [01_Canary_Engine.md](file:///home/utkarsh/Desktop/minor/br1_plan/01_Canary_Engine.md) — Honeypot tokens, system prompt wrapping, substring exfiltration matching.
2. [02_RAG_Poisoning_Scanner.md](file:///home/utkarsh/Desktop/minor/br1_plan/02_RAG_Poisoning_Scanner.md) — Indirect injection detection in retrieved vector database knowledge documents.
3. [03_Threat_Intelligence_Feed.md](file:///home/utkarsh/Desktop/minor/br1_plan/03_Threat_Intelligence_Feed.md) — Self-learning loop clustering blocked attacks via TF-IDF and updating `threat_rules.json`.
4. [04_Security_Dashboard.md](file:///home/utkarsh/Desktop/minor/br1_plan/04_Security_Dashboard.md) — Streamlit command center: live attack feed, telemetry cards, canary flash banner, agent visualizer.
5. [05_Voice_Attack_Surface.md](file:///home/utkarsh/Desktop/minor/br1_plan/05_Voice_Attack_Surface.md) — Whisper speech-to-text client testing spoken adversarial prompts.
6. [06_Chrome_Extension.md](file:///home/utkarsh/Desktop/minor/br1_plan/06_Chrome_Extension.md) — Manifest V3 browser extension intercepting prompts on ChatGPT / Claude.
7. [07_Testing_and_Viva_Demo.md](file:///home/utkarsh/Desktop/minor/br1_plan/07_Testing_and_Viva_Demo.md) — Unit tests, test fixtures, and live viva demonstration scripts.

---

## 3. Strict Inter-Module Linkages for Our Deliverables

| Utkarsh's Deliverable | Connected Component | Communication Method |
|---|---|---|
| `CanaryEngine` | Developer 2's Proxy & Streaming Interceptor | Direct in-process Python import (`core.security_vectors.canary`) |
| `RAGScanner` | Developer 1's Detection Engine | Direct in-process Python import (`core.detection.judge.JudgeAgent`) |
| `ThreatIntelligenceFeed` | Developer 2's SQLite DB & Developer 1's Pattern Hunter | Reads `gateway.db`, writes `core/detection/threat_rules.json` |
| `dashboard/app.py` | Developer 2's FastAPI Gateway | HTTP REST polling (`http://127.0.0.1:8000/api/v1/*`) |
| `voice_client.py` | Developer 2's Gateway API | HTTP POST (`http://127.0.0.1:8000/v1/chat/completions`) |
| `extension/` | Developer 2's Gateway API | HTTP POST via Background Worker (`http://127.0.0.1:8000/api/v1/inspect`) |

---

## 4. Implementation Phasing for Branch `br1`

* **Phase 1: Deterministic Security Vectors** (`canary.py` and `rag_scanner.py`)
* **Phase 2: Self-Learning Intelligence Loop** (`threat_feed.py` & rule generator)
* **Phase 3: Visual Command Center** (`dashboard/app.py`)
* **Phase 4: Multimodal Ingress & Browser Extension** (`voice_client.py` and `extension/`)
* **Phase 5: Automated Verification & Viva Rehearsal** (`tests/test_security_vectors.py`)
