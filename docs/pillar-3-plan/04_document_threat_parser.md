# 04 — Document Threat Parser & Hidden-Text Engine

**Module:** `core/vision/document/`  
**Purpose:** Inspect multi-page PDFs and DOCX documents for structural prompt injections, hidden text layers, and malicious embedded visual assets.

---

## 1. Multi-Page Document Threat Model

Adversaries attach multi-page business documents (PDF/DOCX) to multimodal agent workflows (e.g., automated resume screeners, legal summarizers, financial analysis bots). Within these documents, attackers conceal injection payloads using structural tricks that render the text invisible to human eyes while leaving it fully accessible to LLM document parsers:

1. **PDF Text Render Mode 3:** The PDF standard explicitly defines render mode 3 as *"neither fill nor stroke text"* (making it completely transparent).
2. **Zero-Contrast Typography:** Rendering white text on white backgrounds or matching font color to the underlying table cell background color.
3. **Microscopic Typography:** Injecting text formatted at $\le 1.0$pt font size beneath a logo or in page margins.
4. **Off-Canvas Placement:** Placing text coordinates far outside the visible page boundary (`CropBox`).
5. **DOCX OOXML Vanish Tags:** Applying the `<w:vanish/>` property to hide paragraphs from Microsoft Word rendering while remaining readable by document parsers.

---

## 2. Document Parsing Backends

Sentinel avoids fragile multi-library chains by using two unified, battle-tested parsers:

| Format | Library | Capabilities Exploited |
| :--- | :--- | :--- |
| **PDF** | **PyMuPDF (`fitz`)** | Granular text span extraction with font size, RGB color, bounding box, render mode; page rasterization; embedded raster image extraction. |
| **DOCX** | **`python-docx`** | Paragraph and run traversal; direct OOXML `<w:vanish>` inspection; embedded image extraction from `word/media/`. |

---

## 3. The 5 Structural Hidden-Text Oracles

Sentinel implements five deterministic checks in `core/vision/document/hidden_text_rules.py`:

```
                 PARSED DOCUMENT SPAN
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
   [PDF Document]                    [DOCX Document]
         │                                 │
         ├─► 1. Render Mode == 3?          ├─► 5. OOXML <w:vanish>?
         ├─► 2. ΔE2000(Font, Bg) ≤ 4.5?    └─► 2. ΔE2000(Font, Bg) ≤ 4.5?
         ├─► 3. Font Size ≤ 1.5 pt?
         └─► 4. BBox Outside CropBox?
```

### 1. PDF Render Mode 3 (The Transparency Oracle):
* PyMuPDF's `page.get_text("rawdict")` exposes the exact PDF graphics state for every text span.
* If a span has `render_mode == 3` (invisible) and contains instruction override phrases (e.g., *"ignore"*, *"system prompt"*, *"evaluator"*), it is flagged immediately as a **Layer-1 Deterministic Oracle Violation**.

### 2. Perceptual Color Distance ($\Delta E_{2000}$):
* Naive RGB Euclidean distance fails because human visual perception of color differences is highly non-linear.
* Sentinel extracts the foreground font RGB and the background canvas/cell RGB, converts both to CIELAB color space, and calculates the **CIE $\Delta E_{2000}$** metric:
  $$\Delta E_{2000}(\mathbf{L}_1^*, \mathbf{a}_1^*, \mathbf{b}_1^*, \mathbf{L}_2^*, \mathbf{a}_2^*, \mathbf{b}_2^*) \le 4.5$$
* A $\Delta E_{2000} \le 4.5$ indicates the text is visually imperceptible against the background. If the span contains $> 10$ characters, it is classified as a hidden prompt injection attempt.

### 3. Microscopic Font Detection:
* Absolute condition: Font size $\le 1.5$pt.
* Relative condition: Font size $< 0.15 \times \text{median font size}$ of the active page.
* Legitimate fine print (e.g. legal copyright notices) typically ranges from 5.5pt to 8pt; sub-2pt text serves no legitimate human reading purpose.

### 4. Off-Canvas Placement:
* Sentinel extracts the page's visible `CropBox` rectangle: $[X_0, Y_0, X_1, Y_1]$.
* For each text span, it calculates intersection area with the `CropBox`:
  $$\text{IntersectionArea}(\text{SpanBox}, \text{CropBox}) == 0.0$$
* Spans placed entirely off-canvas are invisible in PDF viewers but ingested by naive text extractors.

### 5. DOCX OOXML `<w:vanish>` Attribute:
* Inspects the run property XML tree: `run._r.get_or_add_rPr().find(qn('w:vanish')) is not None`.
* Any text marked with `vanish` or formatted with zero font height is flagged.

---

## 4. Embedded Raster Image Extraction & Inspection

A document may appear structurally clean while embedding an adversarial infographic or visual jailbreak meme:
1. PyMuPDF enumerates embedded image objects: `doc.get_page_images(page_index)`.
2. Raw image bytes are reconstructed into PIL Images.
3. Each image is passed through the complete **Pillar III Vision Engine** (MobileCLIP semantic scoring + SRM noise filter).
4. Any malicious embedded image contributes directly to the containing page's risk score.

---

## 5. Page-by-Page Risk Rollup: Max-Plus-Mean Formulation

In enterprise environments, attackers frequently embed a single malicious injection page inside a 50-page financial statement or whitepaper.

### Why A Naive Average Fails:
$$\text{AverageRisk} = \frac{100.0 (\text{Page 37}) + 49 \times 0.0}{50} = 2.0 \quad (\text{Falsely Classified as ALLOW!})$$

### The Sentinel Max-Plus-Mean Rollup:
Sentinel aggregates page-level scores using an asymmetric max-plus-mean formulation:

$$R_{\text{doc}} = \min\left( 100.0, \; \max_{p \in P} R_p + \frac{0.15}{|P|} \sum_{p \in P} R_p \right)$$

Where:
* $\max_{p \in P} R_p$ ensures that a single high-risk page ($R_p \ge 80.0$) decisively controls the document's final verdict.
* $\frac{0.15}{|P|} \sum_{p \in P} R_p$ adds a small cumulative penalty for multi-page systemic anomalies without diluting isolated spikes.

