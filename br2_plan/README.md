# Developer 1 (Rohit Verma) — Branch `br2` Master Scope & Execution Plan
**B.Tech Minor Project (IT401) | Group 138 | Department of IT, DTU**  
**Role:** Machine Learning & Multi-Agent Defense Engineer  
**Supervisor:** Dr. Akshay Mool | **Branch:** `br2`

---

## 1. Executive Summary & Dedicated Scope

This directory (`br2_plan/`) contains the complete technical execution blueprint for **Developer 1 (Rohit Verma)** on branch `br2`. 

Rohit is the **Intelligence and Machine Learning Engineer** for the AI Security Gateway. Our mission focuses on the **ingress detection brain**: inspecting raw incoming prompts, orchestrating a multi-agent defense pipeline, computing a defensible composite risk score, and issuing authoritative decisions (`ALLOW`, `FLAG`, `BLOCK`) before any prompt reaches an upstream LLM.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        ROHIT'S CORE MODULES & DELIVERABLES (BRANCH br2)                │
├────┬─────────────────────────────┬─────────────────────────────────┬───────────────────┤
│ #  │ Module Name                 │ Target File Location            │ Architecture Ref  │
├────┼─────────────────────────────┼─────────────────────────────────┼───────────────────┤
│ 1  │ Pattern Hunter Agent        │ core/detection/pattern_hunter.py│ Heuristics & RegEx│
│ 2  │ Semantic Analyst Agent      │ core/detection/semantic_analyst.│ DeBERTa Classifier│
│ 3  │ Behavioral Profiler Agent   │ core/detection/behavioral_profi.│ Temporal Tracker  │
│ 4  │ Judge Consensus Agent       │ core/detection/judge.py         │ Master Decisioner │
│ 5  │ Threat Rules Contract       │ core/detection/threat_rules.json│ Dynamic Signature │
│ 6  │ Benchmarking & Evaluation   │ tests/benchmark_detection.py    │ Precision/Recall  │
│ 7  │ Unit Tests & Viva Playbook  │ tests/test_detection.py         │ QA & Viva Demo    │
└────┴─────────────────────────────┴─────────────────────────────────┴───────────────────┘
```

---

## 2. Directory Navigation & Dedicated Module Guides

Each component of Developer 1's architecture has a dedicated step-by-step implementation guide in this folder:

1. [`01_Pattern_Hunter.md`](file:///Users/rohitverma/Desktop/Minor%20Project/br2_plan/01_Pattern_Hunter.md) — Heuristic regex engine, Base64 decoding scanner, and dynamic mtime-based hot-reloading.
2. [`02_Semantic_Analyst.md`](file:///Users/rohitverma/Desktop/Minor%20Project/br2_plan/02_Semantic_Analyst.md) — Transformer NLP model (`protectai/deberta-v3-base-prompt-injection-v2`), label inversion logic, and truncation safety.
3. [`03_Behavioral_Profiler.md`](file:///Users/rohitverma/Desktop/Minor%20Project/br2_plan/03_Behavioral_Profiler.md) — In-memory sliding-window history tracker, multi-turn escalation detection, and suspicious velocity decay.
4. [`04_Judge_Agent_Consensus.md`](file:///Users/rohitverma/Desktop/Minor%20Project/br2_plan/04_Judge_Agent_Consensus.md) — Multi-agent consensus engine, weighted risk formula, classification thresholds, and explainability reasoning generator.
5. [`05_Threat_Rules_Contract.md`](file:///Users/rohitverma/Desktop/Minor%20Project/br2_plan/05_Threat_Rules_Contract.md) — Shared JSON signature schema, lockless reload mechanism, and ReDoS injection defense.
6. [`06_Benchmarking_and_Evaluation.md`](file:///Users/rohitverma/Desktop/Minor%20Project/br2_plan/06_Benchmarking_and_Evaluation.md) — Scientific evaluation harness measuring Precision, Recall, F1-Score, and sub-agent latency breakdown for DTU report.
7. [`07_Testing_and_Viva_Demo.md`](file:///Users/rohitverma/Desktop/Minor%20Project/br2_plan/07_Testing_and_Viva_Demo.md) — Pytest suite, attack fixtures, and defense script for evaluation with Dr. Akshay Mool.

---

## 3. Strict Inter-Module Linkages for Developer 1

| Rohit's Module | Connected Partner | Communication / Contract Method |
|---|---|---|
| `JudgeAgent` | **Developer 2 (Rupesh)** | Direct Python import in `core/gateway/app.py`: `verdict = judge.evaluate(prompt, session_id)` |
| `JudgeAgent` | **Developer 3 (Utkarsh)** | Direct Python import in `core/security_vectors/rag_scanner.py` to scan retrieved document chunks |
| `PatternHunter` | **Developer 3 (Utkarsh)** | Watches file modification timestamp on `core/detection/threat_rules.json` written by Utkarsh's `ThreatIntelligenceFeed` |
| `JudgeAgent` output | **Developer 2 (Rupesh)** | `gateway.db` stores `verdict["risk_score"]` and `verdict["agent_breakdown"]` for Utkarsh's Dashboard |

---

## 4. Implementation Phasing for Branch `br2`

* **Phase 1: Deterministic Heuristic Core (`pattern_hunter.py` & rule loader)**
  * Implement regex signature scanner, Base64 decoding pre-filter, and file timestamp observer.
* **Phase 2: Deep Semantic Intent Analysis (`semantic_analyst.py`)**
  * Load DeBERTa classification pipeline, enforce strict label probability inversion, and clamp context to 512 tokens.
* **Phase 3: Stateful Behavioral Tracking (`behavioral_profiler.py`)**
  * Build the sliding-window temporal queue, escalation velocity metric, and session memory cleanup.
* **Phase 4: Consensus Synthesis & Integration Master (`judge.py`)**
  * Assemble the 3 agents into `JudgeAgent`, implement composite risk scoring, and synthesize explainable natural language reasons.
* **Phase 5: Automated Verification & Viva Defense (`tests/`)**
  * Write pytest unit tests and benchmark on 200 adversarial/benign prompts to produce academic evaluation metrics.
