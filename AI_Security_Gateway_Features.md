# AI Security Gateway for Detection and Prevention of Prompt Injection Attacks

**B.Tech Minor Project (IT401) — Project-1**
Department of Information Technology, Delhi Technological University

| | |
|---|---|
| **Group No.** | 138 |
| **Member 1** | Rohit Verma (23/IT/138) |
| **Member 2** | Rupesh (23/IT/141) |
| **Member 3** | Utkarsh (23/IT/166) |
| **Supervisor** | Dr. Akshay Mool |

---

## Part A — Synopsis (Approved)

### 1. Introduction

The rapid adoption of Large Language Models (LLMs) and AI-powered applications has created new possibilities in areas such as customer support, healthcare, finance, education and enterprise automation. These applications increasingly process natural-language instructions and may also interact with sensitive data, APIs, databases and external tools.

However, unlike traditional software systems, LLM applications can be influenced by natural-language instructions supplied by users or external content. Attackers can exploit this behavior through techniques such as prompt injection, jailbreaks and instruction manipulation.

This project focuses on developing an AI Security Gateway that acts as an independent security layer between users/applications and an LLM. The gateway will analyze incoming prompts before they reach the AI model and identify potentially malicious or suspicious content.

### 2. Problem Statement

LLM-based applications are vulnerable to attacks in which malicious prompts attempt to change the model's intended behavior, bypass safety restrictions, reveal system instructions or influence the model to perform unauthorized actions.

Existing AI applications often depend primarily on the built-in safety mechanisms of the underlying LLM and may not have an independent security mechanism for analyzing incoming input.

Therefore, there is a need for a security gateway that can detect malicious prompts before they reach the LLM, assess their level of risk, and automatically decide whether to allow, flag or block the request.

### 3. Motivation

As LLMs are increasingly integrated with sensitive information and external tools, a successful prompt injection attack can have consequences beyond generating an inappropriate response. It may potentially lead to sensitive information disclosure, manipulation of application behavior or unauthorized interaction with connected systems.

Recent security research has demonstrated that both direct and indirect prompt injection can affect real-world LLM-integrated applications. OWASP also identifies Prompt Injection as LLM01:2025, highlighting it as a major security risk for generative AI systems.

The motivation of this project is therefore to develop an additional, independent security layer rather than relying completely on the security mechanisms of the underlying AI model.

### 4. Literature Review

#### 4.1 Greshake et al. — *Not What You've Signed Up For* (2023)

Greshake et al. studied indirect prompt injection, where malicious instructions are inserted into external content that an LLM later processes. The research demonstrated that such attacks can manipulate LLM-integrated applications and potentially influence API calls and application behavior. This work highlights the importance of treating external content as potentially untrusted.

#### 4.2 Zou et al. — *Universal and Transferable Adversarial Attacks on Aligned Language Models* (2023)

Zou et al. proposed automated adversarial suffixes capable of bypassing safety mechanisms in aligned language models. Their work demonstrated that carefully constructed prompts can be transferable across different models, showing that relying only on model-level safety mechanisms may not be sufficient.

#### 4.3 OWASP Top 10 for LLM Applications (2023–2025)

OWASP has developed the LLM Top 10 to document major security risks associated with LLM applications. Prompt Injection is identified as a major vulnerability, where crafted inputs can alter the intended behavior of an LLM. OWASP recommends measures such as input filtering, semantic analysis, access control, human approval for high-risk actions and adversarial testing.

### 5. Expected Goals

- [ ] Develop a gateway through which user prompts pass before reaching an LLM.
- [ ] Detect common attacks such as prompt injection, jailbreak attempts and instruction manipulation.
- [ ] Implement a combination of rule-based security checks and NLP/ML-based analysis.
- [ ] Generate a risk score for every analyzed prompt.
- [ ] Classify requests as **Allowed**, **Flagged** or **Blocked** based on the calculated risk.
- [ ] Maintain logs of analyzed requests, detected attacks and security decisions.
- [ ] Develop a web-based dashboard for viewing security events and analytics.

---

## Part B — Advanced Add-on Modules (Selected for Implementation)

The following advanced modules have been selected to extend the approved synopsis into a research-grade platform. Each module is described with its concept, implementation approach and expected outcome.

---

### Add-on 1: Multi-Agent Defense Architecture

**Concept.** Instead of a single detection mechanism, the gateway deploys a team of specialized AI agents that jointly evaluate every prompt — a defense-in-depth design modeled on enterprise security operations centers.

**Agent Roles.**

- **Pattern Hunter** — rule/regex expert detecting known attack signatures.
- **Semantic Analyst** — an LLM agent that reasons about the *intent* of a prompt, not just its keywords.
- **Behavioral Profiler** — tracks per-user/session activity and detects escalating suspicious behavior.
- **Judge Agent** — aggregates all agent opinions into a final verdict with natural-language reasoning (e.g., *"The user is escalating — 3 failed jailbreaks in 5 minutes"*).

**Expected Outcome.** Explainable, layered verdicts that are demonstrably more robust than any single detector; produces a rich architecture diagram and strong viva material.

---

### Add-on 2: Canary Tokens & Honeypot Traps

**Concept.** Fake secrets (canary tokens) are planted inside the system prompt — e.g., `API_KEY = "sk-fake-abc123-canary"`. If an injected prompt manipulates the LLM into revealing the canary and the model's response contains the canary string, a **successful exfiltration attempt** is detected — even when the injection itself looked benign.

**Implementation Approach.** System prompt contains embedded canaries; output-side scanner checks every LLM response for canary strings; a match triggers a high-severity alert in the dashboard and logs.

**Expected Outcome.** Detection of successful (not just attempted) data leakage — a genuinely novel capability at university project level, and a direct countermeasure to the information-disclosure threat identified in the synopsis's motivation.

---

### Add-on 5: Real-Time Streaming Protection

**Concept.** Modern LLM applications stream responses token-by-token (SSE). The gateway intercepts the stream and can terminate it mid-response if the model begins leaking its system prompt or producing policy-violating output.

**Implementation Approach.** FastAPI `StreamingResponse` / SSE proxy; a sliding-window output scanner continuously evaluates streamed chunks; on violation, the stream is cut and the partial response is quarantined and logged.

**Expected Outcome.** Demonstrates that the gateway protects production-style, streaming LLM applications — very few academic projects handle streaming interception.

---

### Add-on 6: Response-Side Guard (Output Filtering)

**Concept.** The approved synopsis covers input-side detection only. This module extends the gateway to a fully **bidirectional security layer** by scanning LLM responses before they reach the user.

**Implementation Approach.** DLP-style checks on every response: PII detection (regex + NER), secret/credential leakage detection, canary-token matching (links to Add-on 2), and policy-violation classification.

**Expected Outcome.** Complete request–response protection pipeline; measurable reduction in sensitive-data exposure.

---

### Add-on 9: Voice-to-Prompt Attack Surface

**Concept.** Many LLM applications now accept voice input. Attackers can *speak* jailbreaks — speech-to-text transcription plus paraphrasing can bypass text-only filters.

**Implementation Approach.** A demo client captures audio, transcribes it via a speech-to-text model (e.g., Whisper), and shows that transcribed/spoken attacks slip past naive keyword filters while the gateway's semantic detection still catches them.

**Expected Outcome.** A memorable live demonstration that the gateway generalizes beyond text prompts to multimodal input.

---

### Add-on 10: Browser Extension / Proxy Mode

**Concept.** The gateway is packaged as a browser extension that intercepts and protects prompts on any LLM chat site (ChatGPT, Claude, etc.) before they are sent.

**Implementation Approach.** Chrome MV3 extension with a content script that forwards page input to the gateway API; the gateway returns an allow/block verdict and optionally rewrites the prompt.

**Expected Outcome.** Strong real-world applicability talking point: the gateway protects users outside a single custom app.

---

### Add-on 11: RAG Poisoning Detection

**Concept.** LLM applications using retrieval-augmented generation (RAG) can be attacked by **poisoning the knowledge base**: an attacker embeds malicious instructions inside a document; when that chunk is retrieved, it hijacks the LLM.

**Implementation Approach.** The gateway inspects every retrieved chunk before it is inserted into the model's context — treating retrieved content as untrusted input (directly extending the indirect-injection work of Greshake et al.).

**Expected Outcome.** Addresses one of the newest (2025–2026) attack classes in generative-AI security; positions the project at the frontier of LLM security research.

---

### Add-on 12: Threat Intelligence Feed

**Concept.** The system continuously improves itself: attack patterns extracted from blocked prompts are generalized into new signatures and pushed as "updates" to connected clients — mirroring how real security products (WAFs, antivirus) distribute threat intelligence.

**Implementation Approach.** Blocked-prompt analysis pipeline that clusters and generalizes attacks into reusable signatures; a simulated feed/distribution mechanism updates client rule sets; versioned rule base with changelog.

**Expected Outcome.** Shows systems-level thinking about how security products operate at scale; a continuously improving detection capability.

---

## Part C — Consolidated Scope Summary

### Core Scope (from Approved Synopsis)

- [x] Independent security gateway proxying all traffic between users and the LLM.
- [x] Rule-based detection (prompt injection, jailbreaks, instruction manipulation).
- [x] NLP/ML-based analysis with a risk score per prompt.
- [x] Three-way decision engine: **Allowed / Flagged / Blocked**.
- [x] Persistent logging of requests, detections and security decisions.
- [x] Web-based dashboard for security events and analytics.

### Advanced Modules (Add-ons 1, 2, 5, 6, 9, 10, 11, 12)

| Add-on | Feature | One-Line Value |
|---|---|---|
| 1 | Multi-Agent Defense Architecture | Layered, explainable AI-agent verdicts |
| 2 | Canary Tokens & Honeypot Traps | Detection of *successful* data exfiltration |
| 5 | Real-Time Streaming Protection | Mid-stream interception and termination (SSE) |
| 6 | Response-Side Guard | Bidirectional DLP on LLM outputs (PII, secrets, canaries) |
| 9 | Voice-to-Prompt Attack Surface | Speech-transcribed attack detection demo |
| 10 | Browser Extension / Proxy Mode | Gateway protection on any LLM chat site |
| 11 | RAG Poisoning Detection | Scanning retrieved content before context insertion |
| 12 | Threat Intelligence Feed | Self-updating signatures distributed to clients |

---

> **Vision Statement.** Together, the core scope and the eight add-on modules position this project as a research-grade AI security platform — covering **input and output**, **text and voice**, **static and streaming**, **local apps and third-party sites**, and **continuously evolving** against novel attacks.
