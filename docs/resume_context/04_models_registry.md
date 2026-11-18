# 04 Machine Learning & Models Registry

This registry documents every machine learning model, embedding generator, neural classifier, statistical model, and OCR engine in the Sentinel codebase.

---

## 1. Master Models Registry Table

| Model / Component | Purpose | Source / Repo ID | Parameter Count | On-Disk Size | Framework / Runtime | Quantization | Device | Where Loaded | Load Strategy | Warmup | Max Seq Len | Batch Size | Status | Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DeBERTa-v3-base Classifier** | Channel A: Ingress prompt injection & jailbreak detection | `protectai/deberta-v3-base-prompt-injection-v2` | 86M params | 704 MB (`model.safetensors`) | HuggingFace Transformers, PyTorch | None (`float32`) | Auto (MPS / CUDA / CPU) | `sentinel/core/detection/semantic_analyst.py:55-72` | Lazy load on demand | Yes (lifespan warmup) | 512 tokens | 1 | **Used** | [VERIFIED sentinel/core/detection/semantic_analyst.py:23-68; sentinel/core/gateway/app.py:52-56] |
| **Llama-3.2-1B-Instruct GGUF** | Stage 2 Deep Security Arbiter (Priority 1 Local) | `bartowski/Llama-3.2-1B-Instruct-GGUF` | 1.23B params | 771 MB (`Llama-3.2-1B-Instruct-Q4_K_M.gguf`) | `llama-cpp-python` / llama.cpp GGML | `Q4_K_M` | Apple Metal GPU (`n_gpu_layers=-1`) / CPU | `sentinel/core/detection/stage2_arbiter.py:205-219` | Lazy load on first Stage 2 call | No | 2048 ctx (256 max tokens) | 1 | **Used** | [VERIFIED sentinel/core/detection/stage2_arbiter.py:108-124, 209-215; sentinel/scripts/download_models.py:46-47] |
| **Phi-3-Mini-4k-Instruct GGUF** | Stage 2 Arbiter Alternative Heavy GGUF | `bartowski/Phi-3-mini-4k-instruct-GGUF` | 3.82B params | ~2.2 GB (when downloaded) | `llama-cpp-python` / llama.cpp GGML | `Q4_K_M` | Apple Metal GPU (`n_gpu_layers=-1`) / CPU | `sentinel/core/detection/stage2_arbiter.py:108-124` | Lazy load | No | 4096 ctx (256 max tokens) | 1 | **Optional** | [VERIFIED sentinel/scripts/download_models.py:41-43] |
| **Llama-Guard-3-8b Cloud API** | Stage 2 Deep Security Arbiter (Priority 2 Cloud) | `meta-llama/llama-guard-3-8b` (Groq API) | 8B params | 0 (Cloud Hosted) | HTTP REST API via HTTPX persistent client | Cloud LPU | Remote Groq Cloud LPU | `sentinel/core/detection/stage2_arbiter.py:129-136` | Initialized if `GROQ_API_KEY` set | No | Cloud managed | 1 | **Optional** | [VERIFIED sentinel/core/detection/stage2_arbiter.py:129-136] |
| **Gemini 1.5 Flash / 3.5 Flash Lite** | Upstream Proxy Target & Stage 2 Priority 3 Fallback | Google Generative AI REST API | Proprietary | 0 (Cloud Hosted) | HTTP REST API via HTTPX client | Cloud TPU | Remote Google Cloud TPU | `sentinel/core/gateway/proxy.py:42-88; sentinel/core/detection/stage2_arbiter.py:138-163` | Per-request | No | Upstream API context | 1 | **Used** | [VERIFIED sentinel/core/gateway/config.py:15-20; sentinel/core/detection/stage2_arbiter.py:138-163] |
| **Gemma-2-2B-IT GGUF** | Pillar V Red-Team Squad: Adversarial Strategist | `bartowski/gemma-2-2b-it-GGUF` | 2.6B params | 1.6 GB (`gemma-2-2b-it-Q4_K_M.gguf`) | `llama-cpp-python` / llama.cpp GGML | `Q4_K_M` | Apple Metal GPU (`n_gpu_layers=-1`) / CPU | `sentinel/core/redteam/mutators/strategist.py:69-90` | Lazy load on first mutation | No | 2048 ctx (256 max tokens) | 1 | **Used** | [VERIFIED sentinel/core/redteam/mutators/strategist.py:57-85; sentinel/scripts/download_models.py:50-52] |
| **GraphCodeBERT Classifier Head** | Pillar II: Code Security Vulnerability Classifier | Custom PyTorch `GraphCodeBERTClassificationHead` | ~1.3M params | Procedurally initialized in memory | PyTorch `nn.Module` (`DFGAttentionLayer`) | None (`float32`) | CPU / Auto | `sentinel/core/codesec/codebert_head.py:66-135` | Initialized on engine startup | No | 512 tokens | 1 | **Used** | [VERIFIED sentinel/core/codesec/codebert_head.py:27-80, 112] |
| **MobileCLIP-S0 Vision Tower** | Pillar III: Visual prompt injection concept embeddings | Custom PyTorch `MobileCLIPVisionTower` | ~11.4M params | Procedurally initialized in memory | PyTorch `nn.Module` (Conv2d hierarchical stem) | None (`float32`) | Auto (MPS / CUDA / CPU) | `sentinel/core/vision/semantic/mobileclip_encoder.py:18-63` | Lazy load on feature extractor | No | 224x224 RGB image | 1 | **Used** | [VERIFIED sentinel/core/vision/semantic/mobileclip_encoder.py:18-63; sentinel/core/vision/config.py:12-16] |
| **MalConv 1D CNN** | Pillar I: Raw binary sequence malware detector | Custom PyTorch `MalConv` | ~1.05M params | Procedurally initialized in memory | PyTorch `nn.Module` (1D gated convolutions) | None (`float32`) | CPU / Auto | `sentinel/core/malware/malconv.py:18-57` | Lazy load on engine startup | No | 2,097,152 bytes (2 MB) | 1 | **Used** | [VERIFIED sentinel/core/malware/malconv.py:18-57; sentinel/core/malware/config.py:13] |
| **MalImg ResNet-18** | Pillar I: 2D Grayscale binary texture family classifier | Custom PyTorch `MalImgResNet18` | ~11.17M params | Procedurally initialized in memory | PyTorch `nn.Module` (1-channel ResNet-18) | None (`float32`) | CPU / Auto | `sentinel/core/malware/malimg.py:40-100` | Lazy load on engine startup | No | 224x224 grayscale image | 1 | **Used** | [VERIFIED sentinel/core/malware/malimg.py:40-100; sentinel/core/malware/config.py:20] |
| **OpenAI Whisper Tiny** | Voice Attack Client: Speech-to-Text transcription | `openai/whisper-tiny` | 39M params | ~151 MB (when fetched) | HuggingFace Transformers, PyTorch | None (`float32`) | CPU | `sentinel/core/security_vectors/voice_client.py:31-48` | Lazy load on audio capture | No | 30 seconds audio | 1 | **Used / Optional** | [VERIFIED sentinel/core/security_vectors/voice_client.py:37-43] |
| **TF-IDF N-Gram Vectorizer** | Automated Threat Intel Feed: Attack clustering | Scikit-Learn `TfidfVectorizer` | Up to 50 n-gram features | In-memory statistical model | Scikit-Learn | `float64` | CPU | `sentinel/core/security_vectors/threat_feed.py:59-80` | Fit on demand during threat feed run | No | 2-4 n-grams across 100 prompts | Up to 100 prompts | **Used** | [VERIFIED sentinel/core/security_vectors/threat_feed.py:27, 59-64] |
| **EasyOCR / PyTesseract / Mock** | Pillar III: Document & image text extraction | `easyocr` (CRAFT+CRNN), `pytesseract`, `MockOCRDriver` | EasyOCR: ~21M params; Mock: 0 | EasyOCR: cached in `~/.EasyOCR` | PyTorch / Tesseract 5 C++ binary / Python | Float32 / Native | GPU/CPU for EasyOCR; CPU for Mock | `sentinel/core/vision/ocr/factory.py:25-75` | Probed dynamically on engine launch | No | Image dimensions | 1 page | **Used** (Mock in CI, EasyOCR probed) | [VERIFIED sentinel/core/vision/ocr/factory.py:33-75; sentinel/scripts/download_models.py:181-182] |
| **Qwen2 Sequence Classifier (`sentinel_model`)** | Pillar IV: Agentic Tool Guardrail classifier | `sentinel_model/` (fine-tuned Qwen2.5-Coder sequence classifier) | 490M params | 1.9 GB (`model.safetensors`), zip: 964 MB | HuggingFace Transformers, PyTorch, SafeTensors | None (`float32`) | CPU | `sentinel/core/detection/tool_guardrail.py:24-50` | Lazy load under mutex `_load_lock` | No | 32,768 tokens (input clamped to 2000 chars) | 1 | **Used** | [VERIFIED sentinel/core/detection/tool_guardrail.py:24-50; sentinel/sentinel_model/config.json:1-66] |

---

## 2. On-Disk Model File Inventory (Command Output Evidence)

Exact filesystem sizes from command execution:
```
sentinel/models/arbiter_gguf/:
total 771M
-rw-rw-r-- 1 utkarsh utkarsh 771M Oct 28 12:37 Llama-3.2-1B-Instruct-Q4_K_M.gguf

sentinel/models/redteam_gguf/:
total 1.6G
-rw-rw-r-- 1 utkarsh utkarsh 1.6G Oct 29 17:47 gemma-2-2b-it-Q4_K_M.gguf

sentinel/models/sentinel_deberta/:
total 715M
-rw-r--r-- 1 utkarsh utkarsh   23 Oct 27 22:44 added_tokens.json
-rw-r--r-- 1 utkarsh utkarsh  194 Oct 27 22:36 calibration.json
-rw-r--r-- 1 utkarsh utkarsh  844 Oct 27 22:44 config.json
-rw------- 1 utkarsh utkarsh 704M Oct 27 22:44 model.safetensors
-rw-r--r-- 1 utkarsh utkarsh  286 Oct 27 22:44 special_tokens_map.json
-rw-r--r-- 1 utkarsh utkarsh 2.4M Oct 27 22:44 spm.model
-rw-r--r-- 1 utkarsh utkarsh 1.3K Oct 27 22:44 tokenizer_config.json
-rw-r--r-- 1 utkarsh utkarsh 8.3M Oct 27 22:44 tokenizer.json

sentinel/sentinel_model/:
total 2.8G
-rw-r--r-- 1 utkarsh utkarsh 2.4K Oct 26 10:12 chat_template.jinja
-rw-r--r-- 1 utkarsh utkarsh 1.5K Oct 26 10:11 config.json
-rw------- 1 utkarsh utkarsh 1.9G Oct 26 10:12 model.safetensors
-rw-rw-r-- 1 utkarsh utkarsh 964M Oct 26 15:54 sentinel_pillar4_model.zip
-rw-r--r-- 1 utkarsh utkarsh  696 Oct 26 10:12 tokenizer_config.json
-rw-r--r-- 1 utkarsh utkarsh  11M Oct 26 10:12 tokenizer.json
```
[VERIFIED command: `ls -lh sentinel/models/*/ sentinel/sentinel_model/`]
