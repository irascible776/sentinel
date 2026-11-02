# Sentinel AI Security Gateway: Architecture Review, Threat Model, and Application-Plane Defense Dossier

## 1. Project Background & System Constraints
- **Project:** Sentinel (AI Security Gateway, DTU B.Tech Group 138).
- **Core Mission:** An ultra-low-latency, multi-agent, cascaded perimeter security gateway sitting between client applications and an upstream Target LLM (Google Gemini Flash `gemini-3.5-flash-lite`).
- **Core Mandates:**
  1. Sub-20ms latency overhead for 95% of safe traffic (local CPU-optimized execution).
  2. Lowest achievable False Positive Rate (FPR) on benign developer & dual-use security tasks (e.g., reverse engineering, packet sniffing, OS internals).
  3. Strict mathematical and architectural independence: Zero self-grading fraud. The target LLM cannot be used as its own judge.

---

## 2. The Two Threat Planes & Architectural State

### Plane A: Control-Plane Attacks (Instruction Hijacking) — [CURRENTLY SOLVED]
- **Threat Vector:** Prompt injections, jailbreaks, persona overrides ("You are now DAN"), system prompt extraction, formatting/delimiter overrides.
- **Current Pipeline:**
  1. **Layer 0 (Normalizer):** Unicode NFKC, invisible zero-width stripping, Cyrillic/homoglyph skeletonization, preserve pristine original for zero-mutation forwarding.
  2. **Layer 1 (Pattern Hunter):** Sub-millisecond compiled regex tripwires (`SIG-001` through `SIG-009` + `threat_rules.json`).
  3. **Layer 2 (Semantic Analyst):** Fine-tuned `microsoft/deberta-v3-base` on InjecGuard Mixture-of-Format (MOF) hard-negative mining (15ms on CPU via ONNX). Disentangled attention recognizes instruction override syntax without false-flagging technical words like "ignore compiler warning".
  4. **Layer 3 (Behavioral Profiler):** Sliding-window temporal velocity and risk escalation tracking (monotonic decay $\tau=180$s).
  5. **Egress Honeypot:** Cryptographic per-request canary tokens (`CANARY-SECRET-UUID`) planted into system prompts with a streaming circuit breaker.

### Plane B: Application-Plane Abuse (Functional Harm & Malware Generation) — [THE ACTIVE PROBLEM]
- **Threat Vector:** Attacks that do NOT attempt to override system instructions or break character. Instead, they use grammatically valid, highly polite, or manipulative academic phrasing to request functional malware, exploit tools, keyloggers, or C2 beacons.
- **The Empirical Gap:** In our recent live penetration test, a request to write a Python keylogger scored only a 1.29% baseline risk because it contained zero prompt-injection keywords or jailbreak syntax. DeBERTa and Regex correctly identified that no *control injection* occurred, leaving a silent vulnerability on the *application abuse* plane.

---

## 3. Critical Architectural Realizations & Bug Fixes
During our deep dive, we identified and corrected two fundamental design mistakes:
1. **The Self-Grading Fraud:** Gemini Flash was mistakenly configured as both the target upstream LLM *and* the Stage 2 Arbiter, sharing weights and failure modes. **Fix:** Gemini Flash is now exclusively the upstream LLM being protected.
2. **The Model Duplication Fallacy:** We caught that Llama Guard 3 cannot be used as both the fast pre-filter (Step 2B) and the final Stage 4 Arbiter. If a manipulative prompt bypasses Llama Guard 3 on the first pass, sending the exact same prompt to the exact same model a second time is mathematically redundant.

---

## 4. The Proposed SOTA Hybrid Defense Architecture

To address advanced attacks utilizing **Manipulative Grammar, Persuasive Adversarial Prompts (PAP, ACL 2024)**, and **Multi-Turn Semantic Slicing (Crescendo Attacks)**, we propose a 4-Pillar defense:

```
                            USER PROMPT
                                 │
                                 ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Pillar 1: Style Neutralization & Intent Canonicalization   │
   │ - Fast transformer strips academic/hypothetical/roleplay  │
   │   fluff to extract raw imperative intent.                  │
   └─────────────────────────────┬──────────────────────────────┘
                                 │
                ┌────────────────┴────────────────┐
                ▼                                 ▼
   ┌───────────────────────────┐     ┌───────────────────────────┐
   │ Control-Plane Detector    │     │ Pillar 2: Ingress Harm    │
   │ DeBERTa-v3 (InjecGuard)   │     │ Llama Guard 3 / WildGuard │
   │ Evaluates Injection /     │     │ Fast discriminative S4/S13│
   │ Instruction Override      │     │ software abuse classifier │
   └────────────┬──────────────┘     └────────────┬──────────────┘
                │                                 │
                └────────────────┬────────────────┘
                                 ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Pillar 3: Multi-Turn Non-Decaying Capability Ledger        │
   │ - Accumulates requested system capabilities (C_session)   │
   │   across turns to detect "salami-slicing" of exploits.    │
   └─────────────────────────────┬──────────────────────────────┘
                                 │
                       (Gray Zone / Discrepancy)
                                 ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Stage 4: Generative Reasoning Arbiter (Local Model)        │
   │ - Local Phi-3 Mini / Mistral-7B (NOT upstream Gemini)      │
   │ - Executes the "Artifact-Reusability Test":                │
   │   "Regardless of backstory, does this yield a functional   │
   │    weaponizable software artifact?"                        │
   └─────────────────────────────┬──────────────────────────────┘
                                 │ ALLOW
                                 ▼
                    UPSTREAM TARGET LLM (Gemini Flash)
                                 │
                                 ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Pillar 4: Egress Code AST & Capability Verification (MOAT) │
   │ - Parses generated Python/C/Bash output into AST.          │
   │ - Scans for deterministic dangerous APIs:                  │
   │   SetWindowsHookEx, GetAsyncKeyState, pynput, raw sockets, │
   │   memory scraping, reverse shell descriptors.              │
   │ - Redacts/Quarantines before returning HTTP 200.           │
   └────────────────────────────────────────────────────────────┘
```

---

## 5. Review Questions for the Expert Panel

1. **Robustness vs. Manipulative Grammar:** Does the combination of Style Neutralization + Ingress Harm Classification + Egress AST Inspection provide gold-standard protection against state-of-the-art Persuasive Adversarial Prompts (PAP) and syntactic obfuscation?
2. **Failure Modes & Blindspots:** Where can this architecture still be broken? How might an elite adversary evade the Ingress Normalizer, the Capability Ledger, and the Egress AST analyzer (e.g., obfuscated Python, `getattr`, dynamically constructed strings, multi-language polyglots)?
3. **Latency & Performance:** Is running Style Neutralization + DeBERTa + Llama Guard 3 achievable within a strict ~20-30ms local CPU budget, or how can the cascade be pruned?
4. **Stage 4 Arbiter Selection:** What is the optimal local reasoning model (parameter size, quantization, inference framework) for the Stage 4 Arbiter to maintain sub-second verification on gray-zone prompts without cloud dependencies?
5. **Concrete Recommendations:** What specific enhancements are required to make this architecture truly production-grade and publication-worthy?
