# 11 Architecture Decisions, Trade-offs & Limitations

This document captures historical design choices, rejected alternatives, known false-negative boundaries, mocked fallbacks, hardcoded defaults, and codebase annotations.

---

## 1. Architectural Decisions & Rejected Alternatives

The following scope and design decisions are documented in project dossiers and specifications:

1. **Drop of Pillar VI (Network & GNN Threat Intelligence)**:
   - *Decision*: Dropped from project scope during v2.0 expansion [STORED RESULT sentinel/Sentinel v2.0 - Scope Expansion Spec.md:18-20].
   - *Rationale*: Network packet capture, flow telemetry, and Graph Neural Networks require host network tap access and infrastructure privilege that an application-layer reverse proxy structurally does not have. Building it would result in a fragmented second product rather than an inline AI security gateway.
2. **Drop of Pillar III Audio Deepfake Classification**:
   - *Decision*: Pillar III was restricted strictly to Vision & Document Threat Analysis (images, PDFs, DOCX); audio deepfake detection was dropped [STORED RESULT sentinel/Sentinel v2.0 - Scope Expansion Spec.md:23-25].
   - *Rationale*: Audio deepfake detection operates on a completely different data modality, requires different model architectures (Wav2Vec2 / RawNet), and was the only un-pretrained model requiring complete training from scratch. Audio in Sentinel was scoped to speech-to-text ingress testing via Whisper in Pillar IV (`voice_client.py`).
3. **Re-framing of Pillar V from Infra Pentesting to AI Red-Teaming**:
   - *Decision*: Reframed from "penetration testing" to "Automated AI Red-Teaming / Adversarial Robustness Testing" (TAP-Lite) [STORED RESULT sentinel/Sentinel v2.0 - Scope Expansion Spec.md:27-29].
   - *Rationale*: Penetration testing implies infrastructure network exploitation, port scanning, and OS privilege escalation. Sentinel is an AI security gateway, so red-teaming was focused directly on LLM/agent prompt injection and jailbreak robustness.
4. **Target Model Independence for the Security Arbiter**:
   - *Decision*: The target model being protected (Google Gemini Flash in `/v1/chat/completions`) is strictly barred from serving as the Stage 2 security arbiter [VERIFIED sentinel/core/detection/stage2_arbiter.py:12-13, 89].
   - *Rationale*: Using the protected model to evaluate its own attack prompts creates self-reinforcing blind spots and shared safety jailbreak vulnerabilities. The Arbiter runs an independent local model (Llama-3.2-1B / Phi-3 via GGUF) or Llama Guard 3.
5. **Two-Layer Corroboration Gating for Vision Defenses**:
   - *Decision*: Soft sensory channels (stego p-values, PGD noise variance) are barred from triggering a `BLOCK` verdict on their own without text/OCR corroboration [VERIFIED sentinel/core/vision/consensus/judge.py:120-145].
   - *Rationale*: Natural photographs often exhibit sensor noise, high-frequency compression artifacts, or pixel histograms that cause false positives in steganalysis. Soft channels are capped at `FLAG` (max score 65.0) to achieve zero false-positive blocks on benign imagery.
6. **Isolated DeBERTa Score Clamping**:
   - *Decision*: A high semantic score from DeBERTa ($\ge 70.0$) without pattern corroboration cannot trigger a `BLOCK` verdict; it is clamped to `[45.0, 74.0]` (`FLAG`) [VERIFIED sentinel/core/detection/judge.py:193-194].
   - *Rationale*: Language models frequently assign high perplexity or elevated injection risk to benign technical prompts discussing security, CTFs, or system architecture. Requiring corroboration eliminates false blocks on legitimate development requests.

---

## 2. Known False-Negative Boundaries & Limitations

1. **Foreign Language & Cross-Lingual Injection**:
   - The text normalizer skeletonizes Cyrillic and Greek homoglyphs to Latin ASCII [VERIFIED sentinel/core/detection/normalizer.py:10-27]. However, low-resource non-Latin scripts (e.g., Devanagari, Arabic, Chinese) or multi-lingual conversational evasion may bypass the English-oriented DeBERTa and keyword rules unless intercepted by Stage 2.
2. **Lossy Compression Steganography**:
   - The `LSBStegoDetector` evaluates the Westfeld & Pfitzmann Chi-Square test on Pairs of Values ($2k, 2k+1$) across pixel histograms [VERIFIED sentinel/core/vision/srm/lsb_detector.py:20-55]. This technique operates on uncompressed or lossless pixel matrices; JPEG compression rewrites high-frequency DCT coefficients, rendering spatial LSB detection ineffective on lossy JPEG images.
3. **Temporal Session Window Limits (Slow-Burn Attacks)**:
   - `BehavioralProfiler` sliding window is configured to 10 minutes (`window_seconds = 600`) [VERIFIED sentinel/core/detection/behavioral_profiler.py:18-21]. If an adversary conducts slow-burn probing with individual turns spaced greater than 10 minutes apart, records are pruned, preventing escalation bonuses from accumulating.
4. **Audio Transcription Acoustic Mismatches**:
   - `voice_client.py` transcribes spoken audio via `openai/whisper-tiny` [VERIFIED sentinel/core/security_vectors/voice_client.py:41]. If an adversarial audio prompt contains subtle acoustic perturbations that cause Whisper to mis-transcribe the attack words into benign text, the downstream text detection pipeline will evaluate only the benign transcript.

---

## 3. Mocked & Procedural Components

1. **`MockOCRDriver` (`sentinel/core/vision/ocr/mock_driver.py`)**:
   - Deterministic fixture driver providing pre-configured OCR results for unit testing and headless CI environments where EasyOCR or Tesseract C++ binaries are not installed [VERIFIED sentinel/core/vision/ocr/mock_driver.py:1-119].
2. **Upstream Mock Provider (`sentinel/core/gateway/proxy.py:17-40`)**:
   - Configured via `UPSTREAM_PROVIDER="mock"`. Generates offline simulated chat completion dictionaries and streaming SSE chunks without requiring external API keys or network connectivity [VERIFIED sentinel/core/gateway/proxy.py:17-40].
3. **Procedural PyTorch Neural Heads**:
   - When external pre-trained checkpoint weights are not loaded from disk, the following PyTorch modules initialize in-memory layers with random/default weights:
     - `MalConv` in `sentinel/core/malware/malconv.py:60-75` [VERIFIED]
     - `MalImgResNet18` in `sentinel/core/malware/malimg.py:102-135` [VERIFIED]
     - `GraphCodeBERTClassificationHead` in `sentinel/core/codesec/codebert_head.py:82-95` [VERIFIED]
     - `MobileCLIPVisionTower` in `sentinel/core/vision/semantic/mobileclip_encoder.py:60-63` [VERIFIED]

---

## 4. Hardcoded Constants & Default Values

| Constant Name | Value | File:Line | Context & Impact |
| :--- | :--- | :--- | :--- |
| `GATEWAY_ADMIN_KEY` | `"gw-admin-secret-key-dtu138"` | `sentinel/core/gateway/config.py:10` | Administrative credential default [VERIFIED] |
| `SECRET_SALT` | `"sentinel_fp_salt_v2"` | `sentinel/core/codesec/secret_scanner.py:54` | Salt string for secret false-positive hashing [VERIFIED] |
| `CANARY_TOKEN_PREFIX` | `"CANARY-SECRET-"` | `sentinel/core/gateway/config.py:39` | Honeytoken prefix injected into system messages [VERIFIED] |
| `window_size` | `150` characters | `sentinel/core/gateway/stream_interceptor.py:21` | Egress sliding window for canary token detection [VERIFIED] |
| `ast_scan_threshold` | `500` characters | `sentinel/core/gateway/stream_interceptor.py:22` | Code accumulation length required to trigger AST taint analysis [VERIFIED] |
| Ingress Blending Weights | `0.20, 0.35, 0.30, 0.15` | `sentinel/core/detection/judge.py:170-173` | Weights for Pattern, Semantic, Intent, and Behavioral signals [VERIFIED] |
| Ingress Decision Thresholds | `40.0` (FLAG), `75.0` (BLOCK) | `sentinel/core/detection/judge.py:238-243` | Decision boundaries for composite risk score [VERIFIED] |
| `tau` | `180.0` seconds | `sentinel/core/detection/behavioral_profiler.py:127` | Exponential decay time constant for past risk scores [VERIFIED] |
| `max_sessions` | `10000` | `sentinel/core/detection/behavioral_profiler.py:22` | In-memory session tracking capacity before 20% eviction [VERIFIED] |
| `MIN_SECRET_ENTROPY` | `3.8` bits/char | `sentinel/core/codesec/config.py:56` | Minimum Shannon entropy required to flag credentials [VERIFIED] |
| `DELTA_E_PERCEPTUAL_THRESHOLD` | `4.5` | `sentinel/core/vision/config.py:42` | Maximum CIE $\Delta E$ distance for hidden text detection [VERIFIED] |
| `MAX_MICRO_FONT_SIZE_PT` | `1.8` pt | `sentinel/core/vision/config.py:38` | Maximum typography font size classified as microscopic [VERIFIED] |
| `MAX_FILE_BYTES` | `33554432` (32 MB) | `sentinel/core/malware/config.py:9` | Maximum binary upload size for malware scanner [VERIFIED] |

---

## 5. Audit of TODO, FIXME & HACK Annotations

A full codebase search was executed:
`grep -rn -E "TODO|FIXME|HACK" sentinel/core/ sentinel/dashboard/ sentinel/scripts/ sentinel/tests/ --exclude="*.json" --exclude="*.bin" --exclude="*.safetensors"` [VERIFIED command output].

- **Source Code Files**: **ZERO occurrences**. There are no pending `TODO`, `FIXME`, or `HACK` comments in active application code.
- **Test Fixtures**: Exactly **1 occurrence**:
  - `sentinel/tests/test_code_security.py:426`:
    ```python
    commented_leak = "# TODO: remove before prod AWS_KEY = AKIA9988776655443322\n"
    ```
    This string is not a developer task note; it is a synthetic test fixture used to verify that the secret scanner detects AWS keys embedded inside code comments (`test_secret_in_comment_detected`) [VERIFIED sentinel/tests/test_code_security.py:424-432].
