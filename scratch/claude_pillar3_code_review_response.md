Claude responded: Pillar III Step 5 code review
Added to memory
sentinel-vision-pillar3.md

Added to memory sentinel-vision-pillar3.md
Pillar III Step 5 code review

I reviewed the design as described in your prompt, not the source. Items marked (confirm) are things I can’t verify from the summary. If you paste image_prep.py, text_presence.py, the consensus judge and the rollup, I can check those directly.

Passing 171/171 shows the code does what the tests expect. It doesn’t show detection quality, false-positive rate, latency or memory. Several issues below are visible from the numbers you gave.

Blockers (fix before any production traffic)

1. The text-presence gate will skip OCR on small injected text.
A threshold of “<0.04 block ratio” means fewer than 4% of 16×16 blocks look text-like. On a 1920×1080 image that is about 324 of 8,100 blocks. A single 50-character caption at 12px covers roughly 25-45 blocks, around 0.4%, so it is classified as a clean photograph and OCR never runs. That is the one-line injection in a large image.

Gate on the count of text-like connected components or line-structured runs, not an area ratio.
Normalize gradients by local contrast, or run the gate on the CLAHE view, so low-contrast text doesn’t fall under the variance threshold.
Better still, use a det-only text detector as the gate.

2. Image coverage gaps at the gateway.
Your summary says the hook blocks image_url data URIs. (Confirm) what happens in each of these cases:

image_url with an https:// URL: if it’s uninspected, that’s a complete bypass, and fetching it separately from the upstream model creates a TOCTOU. Either fetch once, scan, and forward the canonical bytes (with SSRF controls), or reject remote URLs.
Images in earlier messages in the history, in tool results, or in multiple content parts, not just the last user turn.
Other part shapes: Anthropic-style source.base64, Responses-API input_image, string vs object image_url, and PDFs or documents sent as content parts.
Unknown part types should fail closed.
The forwarded bytes must be the canonical PNG, not the original data URI. The anti-TOCTOU property only holds if you forward what you scanned.

3. MockOCRDriver as a “zero-crash” fallback is a fail-open path.
If EasyOCR and Tesseract are both missing in production, the system quietly runs with no OCR, and CI stays green. (Confirm) what Mock returns for real inputs. In production, a missing real backend should fail startup or put the engine in an explicit degraded mode. That mode should FLAG or BLOCK every image the gate considers text-bearing, and raise a health metric. Real-engine integration tests should exist as a separate CI tier, because all 171 tests may be exercising only the mock.

4. The rollup dilutes confirmed findings.
0.65·max + 0.35·mean is capped by construction. One page scoring 100 in a 100-page document gives 0.65×100 + 0.35×1 ≈ 65, probably below your BLOCK threshold. The earlier min(100, max + 0.15·mean) didn’t have this property. Make BLOCK decisions per page or element, from deterministic and corroborated evidence, before any rollup. Use the rollup only for ranking and soft signals, and never let it lower the maximum.

5. The memory budget fails the arithmetic at your own pixel cap.
MAX_IMAGE_PIXELS = 50_000_000 is at odds with <350MB.

Decoded RGB at 50MP is about 150MB (200MB with alpha), before the grayscale, CLAHE, threshold and upscale copies.
The SRM is the biggest risk: 10 float32 output channels at 50MP is about 2GB (a 4MP image is already about 160MB). Sobel gradient maps add about 200MB each.
Lower the analysis cap to around 12-16MP, and reject or downscale above it. Run SRM and Sobel on 512×512 tiles or sampled tiles sequentially, not full-frame.
PIL only warns at MAX_IMAGE_PIXELS and raises at about 2×. Turn DecompressionBombWarning into an error, and check dimensions from the header before decoding.
Confirm ImageFile.LOAD_TRUNCATED_IMAGES is False so truncated files fail closed.

6. The request path may block the event loop, and parsing isn’t isolated.
(Confirm) whether the CPU-bound canonicalize/OCR/SRM/PyMuPDF work runs inside async FastAPI handlers. If so, one slow OCR call stalls all gateway traffic, including text-only. Run vision work in a bounded worker pool, preferably a separate process with rlimits, a wall-clock timeout, and no network. Pillow, libwebp, libtiff and MuPDF parse hostile input, and sandboxing them was one of my P0 items. A concurrency limit of 1-2 vision jobs also bounds memory.

7. CSAM class handling needs a legal and operational decision.
A text-prompt CLIP centroid is not a reliable CSAM detector. It will misfire on ordinary family or beach photos and miss real material. The standard control is hash matching against vetted lists (PhotoDNA, PDQ or a national equivalent), with a legal review of your reporting obligations in the jurisdictions you operate in. Whatever you do, the SOC dashboard’s “bounding box visualizer and redaction inspector” and the audit DB should not render or store images flagged in this class. Keep a hash and metadata only.

High-priority findings

Semantic channel

Your margin > 0.08 and the BLOCK rule “critical semantic match” are uncalibrated in the evidence you gave me. There’s no ROC or FP measurement, just passing tests. Zero-shot CLIP at a small margin shouldn’t BLOCK solo for weapons or violence. FLAG unless corroborated, or make it a per-tenant policy option.
Benign anchors need the categories I listed earlier: GHS pictograms and SDS sheets, product catalogs (knives, tools), game screenshots, medical imagery, lab slides, and terminal or pentest screenshots.
Check that you tile. A 256px center-crop never sees peripheral or small content.

Documents

“Verified document stealth exploit → BLOCK” needs a precise definition. <w:vanish>, tiny font and low ΔE all occur legitimately (TOC and index fields, watermarks, footnotes). Define “verified” as hidden and the hidden text is flagged by the text pipeline. Hidden-ness alone should be FLAG.
The oracles described are all heuristics. The render-vs-text-layer diff (rasterize the page, OCR it, compare with extracted text) is the invariant that covers occlusion, clipping, zero alpha, off layers, ToUnicode remapping, vector-outlined text, and 3-6pt text that a size threshold misses. (Confirm) if it exists. The same goes for embedded-image extraction and OCR, annotations, DOCX headers/footers/comments/tracked deletions/text boxes/alt text/docProps, and PDF incremental updates.
Pick one color metric. You list both CIE76 and ΔE2000. Sample the background from rendered pixels behind the text, not from an assumed page color.
Render mode 3 isn’t mentioned. (Confirm) it isn’t a BLOCK trigger. Searchable scanned PDFs use it for their entire text layer.
Fail-secure BLOCK on unscannable files is right, but make it a distinct verdict code. Encrypted or oversized files are a quarantine decision, not an attack verdict. Add a page and image budget, and treat truncation as a signal.

Canonicalization details to verify

Convert palette (P) images with tRNS through RGBA before flattening, or transparency is mishandled.
Handle 16-bit, CMYK, LA and ICC profiles. Convert to sRGB before stripping.
Use a format allowlist keyed on the decoded format, not the declared MIME. Reject SVG.
Animated GIF, APNG and WebP: which frame is scanned and forwarded? If only frame 0, document that. Forwarding only the canonical PNG makes it safe.
Record source_format and the JPEG quantization tables before canonicalization. The LSB chi-square test is meaningless on decoded JPEG, so skip it when the source was lossy.
Apply the body-size cap (base64 inflates by about 33%) before JSON parse, not just on the streamed image.
Q2: False-positive controls

The structure is right: corroboration gates, soft signals capped at FLAG, and SRM and LSB demoted. The numbers don’t yet show it works. Specific risks for your named traffic:

Code screenshots are the sharpest. They often contain strings like ignore previous instructions, system prompt or DROP TABLE as test fixtures or prompt templates, so “verified OCR injection” can false-BLOCK dev-heavy tenants, including screenshots of this security tooling. Consider downgrading OCR-injection hits to FLAG when the layout looks like monospace code, unless corroborated.
Invoices and scans have paper grain, watermarks (“PAID”, light gray) and JPEG artifacts. These stress SRM, ΔE and the font and color rules.
Architecture diagrams produce garbled OCR. Check that low-OCR-confidence text can’t push the text classifier toward BLOCK.
Regression gate: “zero FP on the corpus” has to state N. Zero failures in N samples gives a 95% upper bound of roughly 3/N, so 1,000 images bounds you at 0.3%. Shadow mode will tell you more than any fixed corpus.
Q3: Memory (<350MB on M1 Air)
The 45MB for MobileCLIP-S0 is plausible, but the weights are the small part. The torch runtime is probably shared with your DeBERTa channel, so measure the incremental peak rather than idle.
EasyOCR (CRAFT plus recognizer) and its activations on large images, plus OpenCV copies, SRM tensors and MPS allocator caching, are what exceed the budget. The MPS allocator doesn’t release memory eagerly. Use torch.mps.empty_cache() and PYTORCH_MPS_HIGH_WATERMARK_RATIO.
Load OCR and CLIP lazily and unload after idle. Measure peak RSS with psutil under worst cases: a 12-16MP image, a 100-page PDF, and 2 concurrent requests. Budgets are per concurrent job, so cap concurrency.
Q1: Remaining edge cases
Redaction operates on the canonical image, which removes most coordinate-mapping bugs. Verify the inverse mapping through any deskew or upscale, pad the boxes, and re-scan the redacted output before forwarding. The stamp text must be constant and contain no matched content. For verified injection, BLOCK is safer than redaction.
Scan endpoints need auth and rate limits. Return coarse verdicts to external callers, with detail only to SOC roles. Don’t write raw OCR text or image bytes to the SQLite audit log without a retention policy. Escape all untrusted text and images in Streamlit Tab 10.
Q4: Production recommendation

Not ready for enforce mode yet. Fix #1-#7 first, plus the document BLOCK definition and the semantic-solo-BLOCK change. Then roll out in stages:

Shadow mode. Run all channels, log verdicts, enforce nothing. Collect FP and FN data on real traffic, with p50/p95/p99 latency and peak RSS on the M1 Air.
Enforce deterministic, high-precision signals first. Only BLOCK on text-pipeline injection hits and confirmed hidden-text-plus-injection. Keep everything else FLAG.
Promote channels individually as measured precision allows. Keep a per-channel kill switch.

Also add these tests:

A real-OCR integration tier.
An adversarial regression corpus (tiny caption in a large image, rotated and low-contrast text, scaling-attack samples, multi-frame and alpha tricks, glyph-remapped PDFs).
Fuzzing of the canonicalizer and parsers on truncated and corrupt inputs.
A load test showing text-only traffic latency is unaffected by concurrent OCR.

Your Pillar V red-team could be extended to generate image probes (typographic overlays, low-contrast text) against this engine as a continuous check.


Create a doc





2 minutes ago
