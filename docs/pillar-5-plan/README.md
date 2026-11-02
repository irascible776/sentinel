# Pillar V — Autonomous AI Red-Teaming & Adversarial Robustness Plan

**Workspace:** `docs/pillar-5-plan/`  
**Purpose:** Central knowledge base and technical specification repository for **Pillar V (Autonomous AI Red-Teaming & Security Auditing Engine)**, formulated through multi-model consensus and peer review across frontier reasoning models (Claude via `ai-helper` and Gemini Council).

---

## 🗺️ Approved Technical Specifications

| Document | Focus Area | Status |
| :--- | :--- | :---: |
| [**`01_model_selection_and_training.md`**](file:///home/utkarsh/Desktop/sentinel/docs/pillar-5-plan/01_model_selection_and_training.md) | Tri-partite lineage independence (Google Gemma-2-2B-IT), Colab ORPO training, M1 unified memory sizing. | ✅ Complete & Approved |
| [**`02_multi_turn_attack_algorithms.md`**](file:///home/utkarsh/Desktop/sentinel/docs/pillar-5-plan/02_multi_turn_attack_algorithms.md) | TAP-Lite search engine, deterministic syntactic mutators, macOS subprocess isolation & thermal duty-cycling. | ✅ Complete & Approved |
| [**`03_judge_and_scoring_mechanisms.md`**](file:///home/utkarsh/Desktop/sentinel/docs/pillar-5-plan/03_judge_and_scoring_mechanisms.md) | Canary honeytoken ground truth, 4-tier evaluation taxonomy, intent preservation guardrail. | ✅ Complete & Approved |
| [**`04_closed_loop_auto_immunization.md`**](file:///home/utkarsh/Desktop/sentinel/docs/pillar-5-plan/04_closed_loop_auto_immunization.md) | Root-cause triage (Canonicalizer vs DeBERTa vs Regex), pre-flight benign validation gate, shadow-mode staging. | ✅ Complete & Approved |
| [**`05_target_integration_and_api.md`**](file:///home/utkarsh/Desktop/sentinel/docs/pillar-5-plan/05_target_integration_and_api.md) | Universal target connectors, Sentinel internal oracle hill-climbing, SQLite schemas, REST API, SOC Tab 9. | ✅ Complete & Approved |
| [**`06_consensus_log.md`**](file:///home/utkarsh/Desktop/sentinel/docs/pillar-5-plan/06_consensus_log.md) | Chronological record of architectural deliberations, Claude peer review verdict, and final system topology. | ✅ Complete & Approved |

---

## 🎯 Approved Core Architecture

1. **Tri-Partite Lineage Independence:**
   * **Ingress Defender:** Microsoft (DeBERTa-v3)
   * **Stage-2 Gray-Zone Arbiter:** Meta (LLaMA-Guard-3 / LLaMA-3.2)
   * **Agentic Tool Guardrail:** Alibaba (Qwen2.5-Coder-0.5B)
   * **Pillar V Attacker:** **Google DeepMind (Gemma-2-2B-IT)** with 256k SentencePiece tokenizer — eliminating shared evaluation echo chambers.

2. **Hardware Harmony (Colab $\to$ M1 Air):**
   * **Training:** Google Colab A100/L4 GPUs using ORPO (Odds Ratio Preference Optimization) with LoRA.
   * **Deployment:** Apple M1 MacBook Air running quantized `Q4_K_M` GGUF (~1.58 GB) via `llama-cpp-python` Metal GPU acceleration.
   * **Subprocess Isolation:** Campaigns run in isolated OS processes, guaranteeing that macOS reclaims 100% of Metal and mmap buffers upon completion.

3. **Objective Ground Truth & Canary Oracles:**
   * Abandons uncalibrated 0–100 scalars for a **4-tier discrete taxonomy** (`REFUSED`, `EVASIVE_NEUTRAL`, `COMPLIED_BENIGN`, `VIOLATION_CONFIRMED`).
   * Ground truth is anchored on **Sentinel Canary Honeytokens** and **sandboxed tool telemetry**, guaranteeing 0% evaluation hallucination.
   * Enforces the **Intent Preservation Test** ($\text{Sim}_{\cos} \ge 0.65$) to prevent Goodhart's gaming.

4. **Zero-False-Positive Self-Hardening:**
   * Triages breaches into Normalization gaps (patches `ast_normalizer.py`), Semantic gaps (queues to DeBERTa), and Lexical gaps (synthesizes regex).
   * Enforces a pre-flight **Benign Validation Gate** (testing against 1,500 enterprise queries) and a **24-hour Shadow Mode** before active blocking.
