Pillar III: Vision & Document Threat Detection Engine — Architectural Review

Reviewed against your stated constraints (M1 8-16GB, <350MB RAM budget for this pillar, <50ms fast path / <600ms deep path, zero-FP mandate, CI without system binaries). Answers below follow your numbering.

1. Model Selection — Zero-Text Visual Semantic Analysis

Recommendation: MobileCLIP-S0 (primary) or S2 (if latency budget allows), not CLIP ViT-B/32 or SigLIP-base.

Model	Params	Approx. memory (fp16)	Fit
CLIP ViT-B/32	~151M	~300-600MB	Too heavy alone — blows your 350MB budget before OCR/SRM/doc parsing even load
SigLIP-base-patch16-224	~203M	~400MB+	Better zero-shot calibration than CLIP, but same memory problem; also no CoreML/mps-optimized reference build
MobileCLIP-S0	~11.4M (image tower)	<50MB quantized	Best fit — purpose-built for exactly this (edge-device, Apple Silicon, CoreML export), strong zero-shot despite tiny size
MobileCLIP-S2	~35M	~80-100MB	Use if S0’s recall on fine-grained concepts (e.g. weapon sub-types) proves insufficient in validation

SigLIP’s sigmoid loss does give it somewhat better-calibrated zero-shot probabilities than CLIP’s softmax contrastive objective, but that calibration advantage doesn’t offset the memory delta here — and MobileCLIP ships Apple-optimized CoreML/ANE builds, which directly targets your M1 constraint in a way neither CLIP nor SigLIP does out of the box.

Concept embedding architecture — precompute everything except the image forward pass:

Build a concept taxonomy with multiple phrasings per concept (prompt-ensembling, as in original CLIP zero-shot classification — average 5-10 template phrasings per concept to reduce template-sensitivity noise): weapons, CBRN, extreme violence, contraband, jailbreak-framing concepts, and explicit benign anchor concepts (invoice, receipt, architecture diagram, code screenshot, slide deck, natural photo, chart/graph).
Run the text tower once, offline, average and L2-normalize each concept’s template embeddings, serialize to a flat tensor keyed by concept ID. Load this at process startup.
At request time: image → image tower → L2-normalize → single matrix multiply against the precomputed concept bank → top-k cosine scores. The text tower never runs at inference — this roughly halves latency and removes tokenizer overhead from the hot path.
Score as a margin against benign anchors, not raw cosine against threat concepts alone: score = cos(img, threat_concept) - max(cos(img, benign_anchor_concepts)). Raw CLIP-family cosine similarities drift upward for any unusual image without a reference frame; margin-against-benign-anchors is the standard mitigation and is directly load-bearing for your zero-FP requirement on diagrams/screenshots, which otherwise tend to score anomalously on raw threat-concept cosine.
Calibrate per-concept thresholds (isotonic or simple sigmoid fit) against a validation set — do not use one global threshold across concepts; different concept categories have different raw-score distributions.
2. OCR Engine & Preprocessing

Recommendation: EasyOCR as primary backend, with a capability-detecting fallback chain, not a hard Tesseract dependency.

Rationale:

EasyOCR is pure PyTorch — no new framework dependency beyond what’s already in your stack (DeBERTa/GraphCodeBERT/Llama are all already PyTorch), no system binary required, runs on mps/CPU, and handles rotated/low-contrast text reasonably well. Model footprint ~150-200MB loaded (detection + English recognition), fits your budget if MobileCLIP-S0 stays light.
PaddleOCR (PP-OCRv4 mobile) has comparable or better accuracy and smaller individual model weights, but pulls in paddlepaddle — an entirely separate inference framework alongside PyTorch, adding dependency-surface and packaging risk for marginal gain here.
Tesseract is lightest on CPU and has no model-download story, but depends on a system binary — exactly the CI risk you flagged. Keep it as an optional fast pre-filter, never a required path.

Resilient abstraction layer:


python
class OCREngine(ABC):
    def extract(self, image: np.ndarray) -> list[OCRSpan]: ...

class OCRFactory:
    def get_engine(self) -> OCREngine:
        # env override > capability probe > deterministic mock
        backend = os.environ.get("SENTINEL_OCR_BACKEND")
        for candidate in self._ordered_candidates(backend):
            if candidate.is_available():   # import probe / shutil.which
                return candidate
        return MockOCRDriver()  # fixture-based, deterministic, CI-safe

MockOCRDriver returns deterministic fixture text keyed by input image hash or a test-mode flag, so your 142+ tests never depend on a real OCR binary/model being present — this directly satisfies your “100% green out-of-the-box” requirement.

Two-stage OCR to protect the <50ms fast path: run a cheap text-presence gate first (MSER regions + stroke-width-transform variance, or a tiny trained binary classifier) before invoking full OCR. Pure photographs with no text (the common case for a lot of enterprise traffic — product photos, headshots, diagrams with no embedded injection text) skip the expensive OCR pass entirely and stay on the fast path.

Preprocessing pipeline for adversarial typography: grayscale → CLAHE (adaptive local contrast — meaningfully better than global histogram equalization for uneven-lighting or deliberately low-contrast injected text) → adaptive Gaussian/Otsu thresholding → 3×3 morphological closing (bridges broken strokes from JPEG artifacts) → deskew via Hough-estimated angle or minAreaRect on text contours → 2× bicubic upscaling for small regions (OCR recall drops sharply below ~20px cap height, which is exactly the regime a “microscopic injected text” attacker would target).

Note: white-text-on-white and sub-pixel overlays embedded in documents are better caught structurally (PDF render-mode / color metadata, §4) than by OCR after rasterization — rasterizing first can lose the exact invisibility signal you’re trying to detect.

3. SRM Filter Bank & the Natural-Texture vs. Adversarial-Noise Problem

Filter bank: implement as a fixed, non-trainable nn.Conv2d (requires_grad=False) with a reduced SRM kernel set rather than the full classical 30-kernel bank (redundant for this use case): first-order horizontal/vertical/diagonal difference kernels (3×3), a second-order Laplacian-type kernel, the classic KV kernel (5×5, from Kodovsky/Fridrich steganalysis literature), and 3×3/5×5 “Square” kernels. 8-12 kernels total is sufficient and keeps the conv pass cheap. Apply quantize-and-truncate after filtering (clip residuals to [-T, T], e.g. T=3) — this is the standard SRM step that suppresses content-dependent magnitude and emphasizes noise statistics rather than raw edge strength.

Features per residual map: local block variance (8×8 blocks → mean/variance of block-variances), residual histogram skewness/kurtosis, Shannon entropy of the residual histogram, high-frequency energy ratio (residual energy / original block energy).

The critical discriminator you asked about — and it isn’t “how much” high-frequency energy, it’s where it sits:

PGD/FGSM perturbations and LSB stego share two properties that dense code screenshots, tables, and receipts don’t:

Spatial uniformity, independent of content. Adversarial noise is applied near-globally regardless of what’s underneath. Natural high-frequency energy (character glyphs, table gridlines, receipt print texture) is tightly co-located with actual content edges — it’s zero in flat/background regions.
Leakage into flat regions. A code screenshot’s whitespace between lines of text has essentially zero residual energy. An image carrying PGD perturbation or LSB payload has measurable structured noise even in those same flat regions, because the perturbation has no content to hide behind there.

So architect two specific, cheap, high-signal checks rather than one blended noise score:

Edge-residual correlation: compute a content edge map (Sobel/Canny) and cross-correlate it against the SRM residual-energy map. High correlation → natural texture (your code/table/receipt case, safely scores low-risk). Low correlation → energy present where there’s no content to justify it → adversarial signature.
Flat-region residual leakage: explicitly measure residual energy within regions the original image classifies as locally flat (low local gradient). This is the single strongest, most literature-grounded signal (it’s the basis of most SRM/”noiseprint” steganalysis detectors) and is exactly the test that keeps a dense, legitimately-noisy financial table from false-positiving — its flat margins stay flat, so it passes.
LSB-specific chi-square test (Westfeld & Pfitzmann) on the actual LSB bit-plane, as a separate, orthogonal, sub-millisecond check — don’t fold this into the generic residual-statistics score; it catches classic LSB stego with very low FP risk independent of the PGD-style detector.

Architect these as two distinct detectors fused at the consensus layer (PGDPerturbationDetector, LSBSteganalysisDetector), not one merged R_noise scalar — blending them loses exactly the specificity that protects you from the catastrophic-FP case you named.

4. Multi-Page Document Handling (PDF/DOCX)

PDF: PyMuPDF (fitz) as the sole parser — it gives span-level text with font, size, color, bounding box, and render mode in one library, plus page rasterization and embedded-image extraction, avoiding a pdfminer+pdf2image+Pillow chain.

DOCX: python-docx, but check the OOXML w:vanish attribute directly (python-docx exposes it as hidden-run formatting) — this is the canonical “hidden text” flag in the format, more deterministic than color-distance heuristics and should be checked first.

For your four hidden-text tricks:

(Render-mode invisible text — check this first, before color heuristics): PDF spec text-render-mode 3 is the canonical “invisible text” primitive (used legitimately for OCR’d-but-invisible text layers, abused for injection). PyMuPDF’s page.get_text("rawdict") exposes render mode per span — a direct, deterministic oracle, not a heuristic.
(a) Font/background color distance: use ΔE2000 (perceptually-weighted), not raw RGB Euclidean distance — two RGB values can be moderately far apart numerically yet visually indistinguishable, and ΔE2000 captures that non-linearity correctly. Flag ΔE ≲ 4-5 (looser than the ~2.3 “just noticeable difference” threshold from color science, to tolerate anti-aliasing artifacts without false-flagging).
(b) Microscopic font: flag absolute size ≤1.5pt, but also flag relative to the page’s median body-text size — a fixed absolute threshold alone risks missing relatively-tiny-but-above-1.5pt tricks, and a purely relative threshold risks flagging legitimate small-but-readable fine print (legal disclaimers, citations).
(c) Off-canvas coordinates: compare each span bbox against the page’s MediaBox/CropBox; flag zero-intersection spans.
(d) Layering/zero-width overlays: detect via stacked spans at near-identical coordinates with conflicting render modes — same PyMuPDF rawdict inspection as the render-mode check above.

Page aggregation: run each extracted raster image through the full image pipeline, producing a per-page vector (hidden_text_ratio, embedded-image scores, etc.). Aggregate document-level risk as max-plus-mean across pages, not a naive average — averaging dilutes one malicious page in a 50-page benign report into a false-benign document score, which directly undermines the enterprise-document use case you care about.

5. Consensus Judge, Decision Tiers, and Redaction

Do not fuse R_ocr_text, R_concept, R_noise, R_doc_structure as a naive weighted linear sum. That’s precisely the mechanism that produces compounding false positives: a busy architecture diagram can independently register moderate-but-individually-benign elevation on several channels (OCR picks up words like “deploy”/”kill switch”; CLIP concept similarity drifts moderately toward “technical schematic”-adjacent concepts; SRM residual stats are moderately elevated from legitimate dense linework) — none alone crosses a threshold, but a linear sum pushes the aggregate over it.

Instead, mirror the pattern you’re already using for Pillar V’s judge — deterministic oracles short-circuit; soft signals require corroboration:

Layer 1 — deterministic oracles → immediate BLOCK, independent of everything else: OCR’d canary honeytoken, PDF render-mode-3 text matching a known injection phrase list, chi-square-positive LSB detection above a strict threshold.
Layer 2 — soft/probabilistic channels require ≥2-channel corroboration before BLOCK/FLAG escalates past FLAG: a single elevated soft signal (CLIP concept margin, SRM residual elevation) alone caps at FLAG (logged to SOC queue, request still allowed — fail-open for availability, fail-visible for audit). Only when ≥2 independent channels each cross their own calibrated “elevated” threshold does it escalate to BLOCK, or when one channel is so extreme it crosses a separate, much higher “certain” threshold on its own.
Reuse the existing text pipeline for OCR’d text — run OCR output through your already-calibrated DeBERTa Channel A + regex Pattern Hunter rather than building a parallel image-specific text-threat classifier. This gives you one well-tuned corroborating channel “for free,” rather than introducing a second, less-validated text-threat scorer that can drift out of sync with your main text engine’s FP tuning.

Tiers:

ALLOW — no oracle hit; soft channels below elevated threshold (or only one mildly elevated, uncorroborated).
FLAG — exactly one soft channel crosses elevated (or OCR-text channel alone crosses its injection threshold, weighted higher than a solo vision-channel hit since the text pipeline is already well-calibrated) → logged for analyst review, request proceeds.
BLOCK — any Layer-1 oracle hit, or ≥2 corroborating soft channels, or one channel past its “certain” threshold.
REDACT_IMAGE — a sub-action, not a separate tier: applies whenever the triggering signal is spatially localizable (OCR gives a bbox; hidden-text detection gives exact span coordinates). Prefer this over hard BLOCK when localizable, so the rest of a legitimate document/image survives. When the signal is global/non-localizable (whole-image CLIP concept hit, global adversarial-perturbation flag), fall back to BLOCK since there’s nothing sensible to redact.

Redaction mechanism: use a solid opaque mask over the detected bbox (plus a small “[REDACTED: policy violation]” stamp for auditability) — not Gaussian blur, which is partially reversible via deconvolution and isn’t a defensible security control for actually removing content, and not inpainting, which fabricates plausible-looking replacement content and is actively misleading to any downstream consumer of the “sanitized” artifact. This is the same logic standard DLP redaction uses for PII.

6. Zero-False-Positive Controls on Enterprise Traffic

This is handled structurally by the corroboration-gated design in §5, but concretely for your named cases (invoices with “override”/”penalty”/”confidential,” dense receipts, code screenshots):

OCR’d text runs through your existing, already-FP-tuned text pipeline rather than a new bespoke classifier — words like “override” or “confidential” in a normal business document are exactly the kind of thing that pipeline is already calibrated against.
CLIP concept scoring uses benign-anchor margin normalization (§1), so “unusual-looking but benign” content (diagrams, dense tables) doesn’t drift toward threat-concept similarity without a comparably strong reference.
SRM noise detectors key off flat-region leakage and edge-residual correlation (§3), which specifically keeps legitimately-noisy/textured content (receipts, tables, code) from registering as adversarial, since their high-frequency energy stays content-correlated.
A solo soft-channel hit caps at FLAG, never BLOCK — no single over-eager channel can unilaterally block legitimate traffic.
Maintain a benign enterprise image/document corpus mirroring your existing benign_corpus.json pattern from Pillar V’s BenignValidationGate, and enforce it as a CI regression gate: any threshold or model change must pass zero-collision against this corpus before merge — the same zero-collision discipline you already apply to the regex auto-hardener, extended to vision.
7. Module Architecture

core/vision/
├── schemas.py                 # VisionScanResult, DocScanResult, ChannelScore, ActionVerdict
├── config.py                  # thresholds, model paths, backend selection (env-driven)
├── preprocessing/
│   ├── image_prep.py          # grayscale, CLAHE, deskew, resize/normalize
│   └── text_presence.py       # cheap MSER/stroke-width gate before full OCR
├── ocr/
│   ├── base.py                # OCREngine ABC
│   ├── easyocr_driver.py
│   ├── tesseract_driver.py     # optional fast pre-filter only
│   ├── mock_driver.py          # deterministic CI fallback
│   └── factory.py              # capability-probe fallback chain
├── semantic/
│   ├── concept_bank.py         # offline-precomputed concept + benign-anchor embeddings
│   ├── mobileclip_encoder.py   # image-tower-only wrapper
│   └── concept_scorer.py       # benign-anchor-margin cosine scoring
├── srm/
│   ├── kernels.py               # fixed SRM kernel bank as torch buffers
│   ├── residual_features.py     # variance/entropy/moment extraction
│   ├── pgd_detector.py          # flat-region leakage + edge-decorrelation
│   └── lsb_detector.py          # chi-square bit-plane steganalysis
├── document/
│   ├── pdf_parser.py            # PyMuPDF: spans, render_mode, bbox, embedded images
│   ├── docx_parser.py           # python-docx: w:vanish, color, embedded images
│   ├── hidden_text_rules.py     # render-mode / ΔE2000 / microfont / off-canvas checks
│   └── page_aggregator.py       # per-page → document-level max-plus-mean rollup
├── consensus/
│   ├── gated_judge.py           # oracle-first, corroboration-gated fusion
│   └── calibration.py           # per-channel thresholds vs. benign corpus
├── redaction/
│   └── redactor.py              # bbox solid-mask redaction
└── pipeline.py                  # scan_image(), scan_document() orchestrators

Integration:

core/gateway/app.py: new /api/v1/scan-image, /api/v1/scan-document routes; and inside /v1/chat/completions / /api/v1/inspect, detect multimodal content blocks and route each through scan_image, feeding its verdict into the existing Master Consensus Judge as one more weighted channel — reuse the fail-closed/asymmetric fusion logic already