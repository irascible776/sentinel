# 01 — Model Selection & Semantic Vision Engine

**Module:** `core/vision/semantic/`  
**Purpose:** Zero-text semantic concept jailbreak detection (detecting dangerous imagery without written text) under strict M1 MacBook Air resource constraints.

---

## 1. Architectural Model Evaluation & Selection

We evaluated four candidate vision-language architectures against Sentinel's target environment (Apple Silicon M1 MacBook Air, $<350$MB RAM budget for Pillar III, $<50$ms fast path):

| Architecture | Image Tower Params | RAM (fp16) | M1 Inference Latency | CoreML / Metal Native | Recommendation |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **OpenAI CLIP ViT-B/32** | ~87M (Total 151M) | ~320–550 MB | 38 ms | No (Generic MPS) | **Rejected:** Blows total memory budget before OCR or document parsers load. |
| **Google SigLIP-base-p16** | ~86M (Total 203M) | ~400–600 MB | 45 ms | No (PyTorch only) | **Rejected:** Better zero-shot calibration, but excessive memory and latency. |
| **Apple MobileCLIP-S2** | ~35M | ~90–120 MB | 22 ms | Yes (Apple Optimized) | **Backup:** High-accuracy fallback if S0 fine-grained recall requires scaling. |
| **Apple MobileCLIP-S0** | **~11.4M** | **< 48 MB** | **11 ms** | **Yes (Apple ANE/MPS)** | **SELECTED (Primary):** Purpose-built for edge Apple Silicon, ultra-low memory, fast. |

### Why MobileCLIP-S0 Wins:
1. **Ultra-Low Memory Footprint:** At 11.4M parameters in the vision tower, quantized weights occupy $< 25$ MB on disk and $< 48$ MB in unified memory.
2. **Apple Silicon Acceleration:** Designed specifically for Apple Neural Engine (ANE) and Metal Performance Shaders (`mps`).
3. **Decoupled Architecture:** Inference runs **image-tower only**. The text tower is executed exclusively offline, completely removing tokenizer and text encoder latency from the runtime path.

---

## 2. Concept Taxonomy & Prompt Ensembling

Raw zero-shot CLIP classification is notoriously sensitive to template phrasing. Sentinel resolves this by deploying **prompt ensembling** (averaging 5–10 template variants per concept) across both Threat Concepts and Benign Anchor Concepts.

### A. Threat Concept Categories
1. **`WEAPON_FIREARM`:**
   - `"a high-resolution photo of a firearm, handgun, or assault rifle"`
   - `"an image depicting a gun, pistol, or ammunition"`
   - `"schematics or 3D CAD models of a 3D-printed firearm"`
2. **`EXPLOSIVE_CBRN`:**
   - `"an improvised explosive device, bomb, or detonator"`
   - `"chemical, biological, radiological, or nuclear hazardous material"`
   - `"pipe bomb with wires and timer mechanism"`
3. **`VIOLENCE_GORE`:**
   - `"extreme physical violence, bloodshed, or severe bodily injury"`
   - `"a depiction of torture, execution, or violent assault"`
4. **`CONTRABAND_ILLICIT`:**
   - `"packaged illicit narcotics, heroin, fentanyl, or drug paraphernalia"`
   - `"counterfeit currency, black market contraband"`
5. **`PHYSICAL_BYPASS`:**
   - `"lockpicking tools manipulating a tumbler mechanism"`
   - `"physical security bypass device attacking an access control lock"`
6. **`VISUAL_JAILBREAK_FRAMING`:**
   - `"a meme or graphic with explicit instructions to bypass AI safety guardrails"`
   - `"a graphic overlay attempting to override system behavior"`

### B. Benign Anchor Categories (Crucial for Zero-FP)
Enterprise traffic often triggers false-positive cosine drift against isolated threat vectors. To prevent this, Sentinel anchors against 7 verified enterprise modalities:
1. **`ENTERPRISE_INVOICE`:** `"a scanned commercial invoice, billing document, or receipt with line items"`
2. **`CODE_SCREENSHOT`:** `"a screenshot of a dark-mode code editor with Python or JavaScript syntax"`
3. **`ARCHITECTURE_DIAGRAM`:** `"a technical software architecture diagram, flowchart, or AWS network topology"`
4. **`FINANCIAL_CHART`:** `"a business performance bar chart, candlestick financial graph, or spreadsheet table"`
5. **`SLIDE_DECK`:** `"a corporate presentation slide with bullet points and business diagrams"`
6. **`NATURAL_SCENERY`:** `"a clean photograph of a landscape, office building, or everyday physical object"`
7. **`DOCUMENT_TYPOGRAPHY`:** `"a black-and-white page of printed legal text or academic journal article"`

---

## 3. Offline Precomputation Architecture & File Format

The text encoder is executed once during initialization/build. Text embeddings are averaged, L2-normalized, and saved to a serialized tensor dictionary:

$$\mathbf{e}_c = \frac{\frac{1}{N} \sum_{i=1}^N \text{TextEncoder}(t_{c,i})}{\left\| \frac{1}{N} \sum_{i=1}^N \text{TextEncoder}(t_{c,i}) \right\|_2}$$

```
core/vision/semantic/
├── concept_bank.py          # Precomputed vectors & anchor definitions
├── concept_scorer.py        # Margin-against-benign cosine matrix math
├── mobileclip_encoder.py    # Torchscript / PyTorch vision tower wrapper
└── weights/
    └── concept_bank.pt      # Precomputed L2-normalized tensor dictionary
```

### Runtime Forward Pass (Sub-15ms):
1. Input PIL image preprocessed: resize to $256 \times 256$, center crop $224 \times 224$, normalize with ImageNet mean/std.
2. Single vision tower pass: $\mathbf{e}_I = \frac{\text{VisionTower}(x)}{\|\text{VisionTower}(x)\|_2} \in \mathbb{R}^{512}$.
3. Single batch matrix multiplication against precomputed tensor bank: $\mathbf{s} = \mathbf{e}_I \cdot \mathbf{E}_{\text{bank}}^T$.

---

## 4. Benign-Anchor Margin Scoring Formulation

Standard CLIP scores drift upward when given complex or abstract images. To achieve **0.0% false positives**, Sentinel scores each threat concept as a **margin against the closest benign anchor**:

$$\text{Margin}(I, c) = \cos(\mathbf{e}_I, \mathbf{e}_c) - \max_{b \in \text{Benign}} \cos(\mathbf{e}_I, \mathbf{e}_b)$$

Where:
* $\cos(\mathbf{e}_I, \mathbf{e}_c)$ is the cosine similarity between the image and threat concept $c$.
* $\max_{b \in \text{Benign}} \cos(\mathbf{e}_I, \mathbf{e}_b)$ is the maximum similarity between the image and all benign enterprise anchors.

### Risk Normalization:
If $\text{Margin}(I, c) \le 0$, the image is closer to a legitimate enterprise document than to the threat concept $\implies \text{Risk} = 0.0$.

For positive margins:
$$\text{RawRisk}(c) = \text{clamp}\left( \frac{\text{Margin}(I, c) - \tau_{\text{floor}}}{\tau_{\text{ceiling}} - \tau_{\text{floor}}} \times 100.0, \; 0.0, \; 100.0 \right)$$
$$\text{SemanticRiskScore} = \max_{c \in \text{Threat}} \text{RawRisk}(c)$$

Default calibration thresholds: $\tau_{\text{floor}} = 0.05$, $\tau_{\text{ceiling}} = 0.28$.

---

## 5. Thread Safety & M1 Memory Orchestration

1. **Lazy Loading:** Model weights are loaded on the first image request using thread-safe double-checked locking (`threading.Lock()`).
2. **Device Selection:** Auto-selects `mps` on Apple Silicon, `cuda` if available on Linux, and `cpu` with 2 execution threads on headless CI.
3. **Inference Mode:** Enforces `torch.inference_mode()` and `torch.set_num_threads(2)` to prevent CPU thread starvation and ensure zero gradient graph retention.

