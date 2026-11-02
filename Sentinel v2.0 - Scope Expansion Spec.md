# Sentinel v2.0 — Scope Expansion Specification

*Prepared for implementation planning. Covers architecture, model choices, datasets, and integration points for five new detection pillars. Implementation details (code structure, APIs, file layout) to be scoped in a follow-up pass.*

## 1. Executive Summary

Sentinel evolves from a single-purpose LLM prompt-injection gateway into a five-pillar AI security platform. Each pillar is a new inspection capability plugged into the existing gateway's architecture — no pillar requires a new deployment model or a separate product.

**Scope decision log** (context on what was cut and why):

- Original proposal included 6 pillars; **Pillar VI (Network/GNN threat intel)** was dropped — it requires infrastructure-layer network tap access Sentinel structurally doesn't have, making it a separate product, not a gateway extension.
- **Pillar III's audio deepfake detection** was dropped — different data modality, different model family, and the only required-from-scratch training task in that pillar. Pillar III is now scoped to vision/document threats only.
- Pillars I, II, IV are unchanged from the original proposal.
- **Pillar V is reframed**: not "penetration testing" (which implies infra/network exploitation Sentinel doesn't do), but **automated AI red-teaming / adversarial robustness testing**, scoped specifically to LLM/agent jailbreak resistance.

**Final scope — 5 pillars:**

1. Malware Binary Analysis
2. Code Security / AST Vulnerability Detection
3. Vision & Document Threat Detection
4. Agentic Runtime Guardrails
5. Automated AI Red-Teaming

Each pillar section below covers: what it detects, the model/architecture, training data, and exactly where it plugs into Sentinel's existing components.

## 2. Current Sentinel Architecture (Baseline)

For reference, what already exists and will be extended:

- **FastAPI Gateway** — `/v1/chat/completions` (OpenAI-compatible proxy), `/api/v1/inspect` (direct prompt check), `/api/v1/stats`, `/api/v1/events`.
- **Ingress Multi-Agent Defense** — Pattern Hunter (regex/signatures), Semantic Analyst (DeBERTa-v3 classifier), Behavioral Profiler (sliding-window session tracking), Master Judge (weighted consensus: 0.25×Pattern + 0.50×Semantic + 0.25×Behavioral).
- **Canary Tokens** — honeytoken injection into system prompts, response-side substring matching for exfiltration detection.
- **Stream Interceptor** — async SSE monitoring, mid-stream abort on policy violation.
- **Response-side DLP** — PII/API-key redaction.
- **RAG Poisoning Scanner** — overlapping-window chunking to quarantine indirect injections in ingested documents.
- **Threat Intelligence Feed** — TF-IDF n-gram clustering on blocked prompts, auto-synthesizes new regex signatures.
- **Chrome Extension (MV3)** — inline interception on ChatGPT/Claude.
- **Voice Attack Client** — Whisper-based adversarial speech testing.
- **SOC Dashboard (Streamlit)** — real-time KPIs, event logs, agent score breakdowns.
- **Audit Logging** — async SQLite WAL persistence.

Every new pillar below reuses one or more of these existing components rather than introducing a parallel system.

## 3. Pillar I — Malware Binary Analysis

**What it detects:** whether an uploaded binary (PE/ELF/Mach-O) is malicious, without executing it, and which malware family it likely belongs to.

**Integration point:** new endpoint `/api/v1/scan-file`, parallel to the existing `/api/v1/inspect`. Verdicts write into the same audit log (SQLite WAL) and surface in the existing `/api/v1/stats` and SOC Dashboard event feed as a new event type.

### Model A — MalConv (raw byte sequence)

- **Architecture:** input parsed as integer byte sequence (0–255), length capped at \~2×10⁶ bytes (pad/truncate). `nn.Embedding` maps each byte to an 8-dim vector. Parallel `nn.Conv1d` layers with wide kernels (k=500, stride=500) capture structural constructs (headers, import tables, shellcode). Gated convolution (element-wise multiply of activated features and linear gates) + `nn.AdaptiveMaxPool1d` for scale-invariant feature extraction.
- **Loss:** `nn.BCEWithLogitsLoss`, binary malicious/benign output.
- **Training note:** this is the most compute-heavy task across all 5 pillars — long sequence length, real GPU time required (hours–days, not a quick fine-tune).

### Model B — MalImg (byte-to-image, transfer learning)

- **Pipeline:** binary mapped to 1D array of byte values, reshaped into a 2D matrix (width determined by file size, e.g. W=128 for \~10KB), resized to 224×224×1 via bilinear interpolation.
- **Architecture:** ResNet-18 / EfficientNet pretrained on ImageNet, adapted for single-channel input, fine-tuned (transfer learning — not trained from scratch).
- **Loss:** multi-class cross-entropy over known family categories (e.g. Ramnit, FakeRean, Yuner).
- **Training note:** lighter lift than MalConv — realistic in days, not weeks, since you're fine-tuning, not training from zero.

### Datasets & Frameworks

- **EMBER 2018 v2** (\~1.1M labeled PE files) — for MalConv.
- **MalImg dataset** (\~9,339 images, 25 families) — for the image classifier.
- PyTorch, Torchvision, `pefile`, `capstone`.

### Verdict combination

MalConv score + MalImg family classification combine into one verdict using the same weighted-consensus pattern as the existing Judge agent — not a new decision framework, an extension of the one already built.

## 4. Pillar II — Code Security / AST Vulnerability Detection

**What it detects:** security vulnerabilities in source code (SQL injection, command injection, insecure deserialization, hardcoded secrets) by understanding code structure, not just text pattern-matching.

**Integration point:** new endpoint `/api/v1/scan-code`, same pattern as `/api/v1/scan-file`. Conceptually reuses the chunking philosophy of the existing RAG Poisoning Scanner — chunking code into functions/files instead of document text.

### Pipeline

1. **AST parsing** — source code (Python, C/C++, Java, JavaScript) parsed via `tree-sitter` (language-agnostic) into Abstract Syntax Trees, exposing parent-child, data-flow, and control-flow relationships while stripping cosmetic variable names.
2. **GraphCodeBERT fine-tuning** — starts from a pretrained GraphCodeBERT/CodeBERT model (Hugging Face). Unlike flat-text BERT, GraphCodeBERT incorporates the data-flow graph (DFG) into its attention mechanism via a graph-structure constraint mask (attention restricted along actual data-flow edges, not arbitrary token distance).
3. **Target CWEs:**

- CWE-89 (SQL Injection)
- CWE-78 (OS Command Injection)
- CWE-502 (Insecure Deserialization — `pickle.loads`, `yaml.unsafe_load`)
- CWE-798 (Hardcoded secrets/API keys/crypto keys)

4. **Secret detection head** — a dense classification head on top of CodeBERT, trained for high-entropy pattern + contextual variable-assignment detection (leaked credentials, AWS keys, JWTs).

**Training note:** this is the most tractable pillar from a compute standpoint — fine-tuning a pretrained transformer's classification head on an existing labeled dataset, not training from scratch.

### Datasets & Frameworks

- **CodeXGLUE**, **Draper VDISC**, **CWEBench**, **Big-Clone-Bench**.
- `tree-sitter`, PyTorch, Hugging Face `transformers`, `networkx`.

### Output shape

Flagged code segments return with CWE category + confidence score, in the same JSON-verdict shape as existing prompt-injection blocks — consistent API design across the whole gateway.

## 5. Pillar III — Vision & Document Threat Detection

**Scope note:** audio deepfake detection was dropped from the original proposal (different modality, different model family, heaviest training lift). This pillar is now scoped to image/visual threats only, keeping it a cohesive unit around one input type and one embedding approach.

**What it detects:** (1) prompt injections hidden inside images submitted to multimodal LLMs, (2) steganographic payloads or adversarial perturbations embedded in images.

**Integration point:** extends the existing **ingress detection ensemble** directly — two new detector agents run alongside Pattern Hunter / Semantic Analyst / Behavioral Profiler whenever a request includes an image. Their scores feed into the existing weighted-consensus Judge formula as two additional inputs, rather than a separate decision system.

### Detector 1 — Vision-Language Jailbreak Defense

- **Dual pipeline:** (a) OCR (Tesseract/EasyOCR) extracts any rendered text from the image and routes it through Sentinel's **existing text analysis layer** (Pattern Hunter + Semantic Analyst) — no new text-classification model needed. (b) CLIP-based cross-modal encoder computes cosine similarity between the image's embedding and a small set of predefined "threat concept" text embeddings (e.g. "an image containing text instructing system override"). High similarity triggers rejection.
- **Training note:** near-zero training — CLIP is used pretrained, as-is. This is inference + a similarity threshold, not model training.

### Detector 2 — Steganographic & Adversarial Perturbation Detection

- **Mechanism:** Spatial Rich Model (SRM) feature extractor + high-pass convolutional filter (`nn.Conv2d` initialized with predefined residual kernels) isolates high-frequency spatial noise. A secondary classifier evaluates visual entropy/local variance to flag LSB steganography and adversarial perturbation (FGSM/PGD-style noise).
- **Training note:** lighter than a full vision model — mostly signal-processing feature extraction + a small classifier head.

### Datasets & Frameworks

- **Visual Jailbreak Dataset (VJD)**, **ImageNet-Adversarial**.
- OpenCV, PyTorch, Hugging Face `transformers` (CLIP).

### Why this cut improves the pillar

Dropping audio removes the only required-from-scratch training task in this pillar (ResNet-LSTM on ASVspoof spectrograms) and keeps the pillar unified around one input modality and one core technique (embedding similarity + frequency analysis) rather than a grab-bag of unrelated detectors.

## 6. Pillar IV — Agentic Runtime Guardrails

**What it detects:** malicious or dangerous tool calls generated by an AI agent (shell commands, SQL queries, API calls) before they execute, plus memory/context poisoning in agents with long-term vector memory.

**Integration point:** this is the closest-fit extension in the whole roadmap — it clones the existing **Stream Interceptor** pattern (which already inspects streaming text mid-flight) and applies the same "intercept before it lands" philosophy to tool-call JSON payloads instead of streamed tokens.

### 1. Tool-Call Argument Inspection Engine

When an agent generates a tool call (e.g. `execute_sql(query=...)`, `run_terminal_command(cmd=...)`), Sentinel intercepts the payload before execution, in three layers — directly mirroring the existing ingress ensemble's structure:

- **JSON Schema Validation** — argument types checked against defined structural schemas.
- **Deterministic Regex Filtering** — same style as the existing Pattern Hunter; blocks known injection syntax (`; rm -rf`, `&&`, `|`, `$(...)`, `UNION SELECT`).
- **Semantic Threat Classification** — same style as the existing Semantic Analyst; a light DistilBERT model fine-tuned on shell-command/SQL-injection corpora catches obfuscated payloads (e.g. base64-encoded commands).

### 2. Memory Poisoning & Context Guardrails

For agents with vector-database memory (Pinecone/ChromaDB/FAISS), Sentinel computes cosine similarity between newly retrieved memory chunks and known malicious-instruction embedding patterns. A secondary transformer check flags meta-instructions ("System Override:", "From now on, do the following:") in retrieved context before it's prepended to the prompt stack — conceptually the same quarantine logic as the existing RAG Poisoning Scanner, applied to agent memory instead of ingested documents.

**Training note:** lightest training lift of the five pillars. The regex layer needs no training at all; the DistilBERT classifier is small and fast to fine-tune on a combination of public SQLi/shell-injection payload lists plus synthetically generated obfuscated variants.

### Datasets & Frameworks

- Public SQLi/command-injection payload corpora + synthetic obfuscated variants (self-generated).
- Hugging Face `transformers` (DistilBERT), vector embedding libraries matching whichever vector DB is targeted.

## 7. Pillar V — Automated AI Red-Teaming

**Framing note:** this pillar is deliberately named "automated AI red-teaming / adversarial robustness testing," not "penetration testing." Real penetration testing covers network/infrastructure exploitation — a different domain and skillset. This pillar tests LLM/agent jailbreak resistance only.

**What it does:** continuously and automatically tests whether Sentinel's own gateway (or any LLM-backed endpoint) can be jailbroken through conversation, instead of relying on a fixed list of known attacks.

**Integration point:** sits outside the gateway as an external tool that targets it — same relationship the existing Voice Attack Client has to Sentinel, but automated and iterative instead of one-shot. Critically, its output feeds back into the **existing Threat Intelligence Feed** (TF-IDF signature synthesis) — successful bypasses become new detection signatures automatically, closing the loop between testing and detection using a component Sentinel already has.

### Attacker–Defender–Judge Loop

1. **Attacker Agent** (an LLM called via API — not trained, just prompted) formulates an adversarial prompt and sends it to the target endpoint.
2. **Judge Model** (a fine-tuned classifier, e.g. RoBERTa, or another LLM call) evaluates whether the target's response constitutes a successful breach or a refusal.
3. **Refinement loop:** if the attack fails, the Attacker Agent analyzes the refusal and iteratively refines strategy — roleplay framing, translation obfuscation, character-level encoding (Base64/ROT13), payload splitting — across up to N conversation turns.
4. Successful bypasses are logged and piped into the Threat Intelligence Feed as new raw material for signature synthesis.

**Training note:** no model training required for the core loop — this is orchestration logic (API calls + prompt engineering + a scoring function), not new model development. The only pre-existing "learning" component involved is the already-built TF-IDF clustering in the Threat Intel Feed, which is classical NLP, not deep learning.

### Benchmark Standards to Test Against

- **OWASP Top 10 for LLMs** (prompt leakage, insecure output handling, training data poisoning, supply chain vulnerabilities).
- **MITRE ATLAS** framework (TTP mapping for AI systems).
- **HarmBench / AdvGLUE** (adversarial robustness benchmarks).

### Output

Cryptographic audit logs + compliance-style reporting (PDF/JSON) covering vulnerability coverage, refusal success rates, and policy remediation suggestions — extends the existing audit logging infrastructure rather than building new reporting from scratch.

## 8. Integration Architecture (At a Glance)

&#91;embedded content: 5 pillars · shared gateway core\]

All five pillars sit on top of the same existing Sentinel core (ingress ensemble, stream interceptor, threat intel feed, audit log) — none require a separate deployment or data path.

## 9. Datasets, Frameworks & Training Load Summary

| Pillar | Primary Datasets | Key Frameworks | Training Load |
| --- | --- | --- | --- |
| I — Malware Binary | EMBER 2018 v2 (1.1M PE files), MalImg (9,339 images, 25 families) | PyTorch, Torchvision, pefile, capstone | Heaviest — MalConv trains from scratch on long byte sequences; MalImg is lighter transfer learning |
| II — Code Security | CodeXGLUE, Draper VDISC, CWEBench, Big-Clone-Bench | tree-sitter, PyTorch, Hugging Face transformers, networkx | Light — fine-tuning a pretrained GraphCodeBERT classification head |
| III — Vision & Docs | Visual Jailbreak Dataset (VJD), ImageNet-Adversarial | OpenCV, PyTorch, Hugging Face transformers (CLIP) | Near-zero — CLIP used pretrained; SRM detector is mostly signal processing + small classifier |
| IV — Agentic Guardrails | Public SQLi/command-injection payload corpora + self-generated obfuscated variants | Hugging Face transformers (DistilBERT), vector embedding libs | Lightest — small model, small dataset, fast iteration |
| V — Red-Teaming | OWASP Top 10 for LLMs, MITRE ATLAS, HarmBench, AdvGLUE (used as benchmarks, not training data) | LLM APIs (Attacker/Judge), existing TF-IDF threat feed | None — pure orchestration, no model training |

## 10. Next Steps

This spec covers architecture, model choices, and integration points. Implementation planning (file structure, API contracts, repo layout, build order) is a separate follow-up pass, informed by the time-and-training-load ordering below.

**Suggested build order** (lightest/fastest-to-verify first, to get working end-to-end pipelines early):

1. Pillar IV (Agentic Guardrails) — lightest training lift, closest architectural fit.
2. Pillar II (Code Security) — tractable fine-tuning, existing labeled datasets.
3. Pillar III (Vision & Docs) — mostly pretrained-model inference.
4. Pillar V (Red-Teaming) — orchestration-heavy, benefits from Pillars I–IV existing first (more surface area to test).
5. Pillar I (Malware Binary Analysis) — heaviest compute/training lift, tackle once the gateway extension pattern is proven on the lighter pillars.

Open questions to resolve before implementation begins:

- Compute availability for Pillar I's MalConv training (sequence length \~2M bytes is the heaviest single training task across all five pillars).
- Which LLM(s) to use for Pillar V's Attacker/Judge roles, and associated API cost/rate limits for iterative multi-turn loops.
- Whether Pillar IV's vector-memory poisoning check needs to support multiple vector DB backends (Pinecone/ChromaDB/FAISS) or can target one for v1.
