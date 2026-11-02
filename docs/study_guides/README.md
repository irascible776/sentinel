# Sentinel v2.0 — Comprehensive Engineering & Architectural Study Guide

Welcome to the definitive study guide for the **Sentinel v2.0 AI Security Gateway**. This repository of technical guides explains each pillar of the defense architecture in simple, first-principles terms, detailing **what each component does**, **how it works under the hood**, and **why specific models, features, and algorithms were chosen over alternatives**.

---

## 🗺️ Five-Pillar Architectural Matrix

| Pillar | Focus Area | Primary Techniques | Models & Algorithms | Key Trade-off / Choice Justification |
| :--- | :--- | :--- | :--- | :--- |
| **Pillar I** | **Malware Binary Analysis** | Raw Byte Stream CNN + Visual 2D Byte Density | **MalConv** (Gated 1D-CNN) + **MalImg** (ResNet-18 Transfer Learning) + Static PE/ELF Header & Entropy Analysis | **Static without Execution:** Dynamic sandboxing is too slow for gateway latency (~100ms budget) and vulnerable to VM-detection evasions; dual raw-byte + 2D spatial features bypass disassembly failures on packed binaries. |
| **Pillar II** | **Code Security & AST Analysis** | Abstract Syntax Trees + Graph Data-Flow Transformers | **Tree-sitter** AST Extraction + **GraphCodeBERT** / CodeBERT + Secret Entropy Head | **Code Structure over Text:** Regex matches text patterns (prone to high false positives and comment bypasses); GraphCodeBERT embeds semantic data-flow edges (DFG) directly into transformer attention masks. |
| **Pillar III** | **Vision & Document Threats** | Multimodal Jailbreak Defense + Spatial Noise Analysis | **CLIP** Cross-Modal Cosine Embedding + **OCR** Pipeline + **Spatial Rich Models (SRM)** High-Pass ResNet | **Multi-Spectrum Vision Defense:** OCR alone misses visual text injection; CLIP detects semantic jailbreak concepts; SRM isolates high-frequency adversarial perturbations and LSB steganography. |
| **Pillar IV** | **Agentic Runtime Guardrails** | Intercepting Autonomous Agent Tool Calls Mid-Flight | **Qwen2.5-Coder-0.5B-Instruct LoRA** + **AST Normalizer** + **Multi-Base SSRF IP Filter** + SHA-256 Cache | **Code-Aware LLM over Text Classifier:** Standard NLP classifiers fail on shell syntax and nested JSON; Qwen2.5-Coder deeply understands code/AST semantics; hybrid multi-layer defense provides <0.2ms cached response. |
| **Pillar V** | **Automated AI Red-Teaming** | Continuous Adversarial Robustness & Jailbreak Probing | **Automated Multi-Turn Jailbreak Engine** (PAIR / TAP / Tree-of-Thought mutation) | **Continuous Probing over Static Lists:** Static attack dictionaries go obsolete immediately; multi-turn adaptive mutations actively uncover blind spots in gateway classifiers. |

---

## 📚 Pillar Study Guides

- **[Pillar I: Malware Binary Analysis (Completed)](./pillar_1_malware_analysis.md)**
- **[Pillar IV: Agentic Runtime Guardrails (Completed)](./pillar_4_agentic_guardrails.md)**
- **[Pillar II: Code Security / AST Vulnerability Detection (Completed)](./pillar_2_code_security.md)**
- **[Pillar III: Vision & Document Threat Detection (Upcoming)](./pillar_3_vision_threats.md)**
- **[Pillar V: Automated AI Red-Teaming (Upcoming)](./pillar_5_red_teaming.md)**

---

## 🛡️ Core Architectural Principles

1. **Defense-in-Depth (Multi-Layer Ensembles):**
   No single machine learning model or rule is infallible. Every pillar pairs ultra-fast deterministic pre-flight heuristics (<1ms) with deep machine learning models (30–150ms) and weighted consensus scoring.
2. **CPU-First Production Realism:**
   All models are optimized to execute on commodity dual-core CPU hardware using `torch.inference_mode()`, constrained thread pools (`torch.set_num_threads(2)`), and thread-safe SHA-256 LRU caching.
3. **Fail-Closed Security Posture:**
   Corrupted inputs, oversized payloads (>64KB / >2MB), and parsing anomalies default to quarantine or rejection rather than letting malformed inputs bypass detection.
