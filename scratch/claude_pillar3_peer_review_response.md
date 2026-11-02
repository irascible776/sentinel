Claude responded: Pillar III peer review
Updated memory
sentinel-vision-pillar3.md

Updated memory sentinel-vision-pillar3.md
Pillar III peer review

I’m working from your summary, not the six docs themselves. Where a point depends on a number, such as CLIP cosine ranges, treat it as a hypothesis to measure on your own corpus.

Verdict: conditional approval. The modular decomposition is sound. The decision to reuse the ingress pipeline for OCR text is the best part. Seven items below should be fixed in the design before coding, because they change module boundaries.

1. Adversarial bypass and blind spots

Scanner/victim divergence is the biggest structural gap. The plan scans one rendering of the image, but the downstream VLM sees something else.

Scaling attacks. Images can be crafted so that a hidden prompt appears only after the VLM’s own resize (Anamorpher-style). Scanning at native resolution misses it. Scan at the resolutions and interpolation modes (nearest, bilinear, bicubic) your target models use.
Frames and layers. Scanning only frame 0 misses animated GIF, APNG, WebP and multi-page TIFF. Alpha is the same problem: text can be visible only when an RGBA image is composited on a dark background. Apply EXIF orientation, composite alpha, and normalize color space before scanning.
OCR-readable vs VLM-readable.
Deskew of ±45° does not cover 90°, 180° or 270° rotation, vertical text, curved or warped text, or mirrored text.
Otsu thresholding can erase near-background-color text, and per-channel or low-contrast text survives only in contrast-amplified views.
Fix: run OCR on several views (original, CLAHE, inverted, per-channel contrast-stretched, 4 rotations). A text detector is much cheaper than recognition, so use it per view and recognize only where it fires.
The fast-path gate is a bypass target. A gradient/stroke-variance gate decides whether OCR runs, and attackers can texture text to fail it. EasyOCR on CPU also won’t hit <50ms, which is the pressure creating the gate. Use a det-only mobile detector (DBNet/PaddleOCR-det class) as the gate. If you must skip OCR, require high confidence of “no text”, and relax the SLO to async for text-bearing images instead of weakening detection.
MobileCLIP preprocessing crops. At 256px resize plus center crop, small or peripheral content is never evaluated. Use a global view plus overlapping tiles with max-pooling. CLIP-family models are also typographically attackable: overlaid text dominates the embedding.
SRM adaptive attacks. The detector targets global additive noise. It misses localized adversarial patches, low-frequency or flow-field warps, and perturbations masked to high-gradient regions, which satisfy both 
𝐶
edge
C
edge
	​

 and 
𝐿
flat
L
flat
	​

 by construction. It is also fragile to JPEG recompression and resizing. Rank this below visual prompt injection in your threat model.
Missing signal classes.
QR/barcode payloads (decode them and route the text through the pipeline).
Metadata text (EXIF UserComment, XMP, PNG tEXt, filename, alt text).
SVG (reject, or rasterize in a sandbox).
Text split across fragments that only a VLM reassembles.
Documents: unify on render-vs-text-layer diff. Your five oracles are heuristics for one underlying invariant: text that is extracted but not visible. Rasterize each page, OCR it, and diff against the text layer. That one check catches several attacks the five oracles miss:
Text hidden under an opaque shape.
Clipped text and zero-alpha text (ca=0).
Optional-content layers that are off by default.
ToUnicode glyph remapping, where rendered glyphs differ from the extracted text.
Text as vector outlines or Type 3 fonts, which have no text layer at all, so rasterize and OCR pages.
DOCX surface beyond w:vanish. Check w:webHidden, tracked deletions (w:delText), headers/footers, footnotes, text boxes (DrawingML/VML), image alt text, core.xml properties, custom XML, comments, and external relationships. Extract with several parsers, since PyMuPDF, pdfminer and pdftotext disagree.
Polyglots and parser confusion.
PDF incremental updates and multiple %%EOF.
ZIP central-directory vs local-header mismatches and duplicate entries.
Encrypted PDFs with an empty password.
JPEG/ZIP/PDF hybrids.
Embedded images as raw XObjects with SMask or Decode arrays, which differ from the composited appearance. Extract by rendering, not by raw stream.

TOCTOU is an architectural hole. For image_url in /v1/chat/completions, if the gateway scans and the upstream model re-fetches the URL, an attacker can serve different bytes to each. Fetch once, scan, and forward the exact scanned bytes. The fetch also needs SSRF protection (private ranges, redirects, DNS rebinding).

A design option worth considering. A tenant mode where the gateway never forwards the image and forwards only its own extracted text removes scaling attacks, adversarial noise, stego and metadata in one stroke, at the cost of capability.

2. False-positive risk

Thresholds I’d change:

Render mode 3 is not an attack signature. It’s how every OCR’d or searchable-scanned PDF stores its text layer, including those from ocrmypdf and Acrobat. Keyword-gated Layer-1 BLOCK will also block legitimate security-training PDFs. Treat mode 3 as routing information: run the text through the full text pipeline, and flag only when it doesn’t align with an underlying image region.
Font-size rule. < 0.15 × median breaks on slides: with 40pt median, 6pt footers fire. Use an absolute floor, and compute effective size after the text matrix and CTM (1pt font × 12× scaling is common).
ΔE2000 ≤ 4.5. Legitimate watermarks, ghost placeholders, light-gray footers and disabled UI text will hit this. Background must be sampled from the rendered pixels behind the text bbox, not assumed page color. Also tie it to opacity and occlusion, not just color.
LSB chi-square as a deterministic BLOCK.
It’s a statistical test, so it contradicts your own corroboration rule.
It false-positives on histogram-equalized, dithered and flat-palette images (medical scans, screenshots).
It only detects full-capacity sequential embedding, and is blind to JPEG.
A 200-image PDF gives you 200 chances at p>0.999.
LSB payload is invisible to VLMs, so it’s a C2/exfil signal rather than an injection one. Demote it to a soft signal, or attempt payload extraction and route the extracted bytes through the text pipeline.
Margin 
𝜏
=
0.05
,
0.28
τ=0.05,0.28. I suspect 0.28 is unreachable. Image-text cosines in CLIP-style spaces occupy a narrow band, so most images would score near 0 and recall collapses. Calibrate on labeled data (percentiles, or a logistic/Platt map on margins) rather than fixing constants.
SRM “zero leakage on benign.” That claim fails on scanned receipts (paper grain, halftone, moiré), camera photos, JPEG blocking, and gradient slide backgrounds with dithering. Dark-mode IDE screenshots are probably fine, but test them. Scans are the realistic FP source.

Taxonomy gaps. Margin-against-benign makes any out-of-distribution image look threatening. Add benign anchors for:

GHS hazard pictograms and safety data sheets (the exploding-bomb pictogram is on every SDS).
Medical and anatomical imagery.
Product catalogs (knives, tools, airsoft).
Game screenshots and film stills.
Lab and chemistry slides.
Terminal and pentest screenshots (these will hit “Jailbreak Framing”).
Maps and news photos.

Consider an OOD/”none of the above” path instead of letting unmodeled content default to threat.

Consensus structure.

Per signal class, not uniform. The OCR-text-through-ingress channel is high precision and should be able to BLOCK solo. SRM and semantic margin are anomaly channels that need corroboration. Uniform “solo soft → FLAG” would let a pure typographic injection through if the text channels score under 92.
Independence. “≥2 corroborating channels” is weak if channels share inputs. Require evidence from different families (textual, forensic, semantic).
Provenance. Imperative instructions addressed to an AI inside an image are rarer in benign content than in typed prompts. Image-derived text arguably warrants a stricter threshold, with OCR-confidence-aware handling.
Calibration. “92.0” should mean the same precision across channels. Calibrate each to probabilities.
OCR-noise tolerance. SIG-001/002 regexes need fuzzy matching.
Regression gate. A “zero-FP” corpus result is only as strong as N: zero failures in N samples gives a 95% upper bound of about 3/N. Define N, add shadow/monitor-only rollout, and track drift.
3. Redaction trust boundary

Yes, there are real implications:

Rebuild from decoded pixels. Never copy container bytes or patch in place. Write a fresh file and verify no trailing data. (Cf. aCropalypse, where the original survived after the edit.)
Hidden copies of the original. EXIF thumbnails, MPF secondary images, HDR gain maps, HEIC auxiliary images, APNG/TIFF extra frames, PNG ancillary chunks (eXIf, iCCP, iTXt). Strip all metadata after applying orientation and converting to sRGB, or colors and rotation shift.
Alpha. Setting alpha to 255 in the mask region isn’t enough if you leave RGB data under alpha=0 pixels. Overwrite RGB, then flatten.
Coordinate mapping. Boxes found on the preprocessed image (2× upscale, deskew, crops, EXIF transform) must map back through the inverse chain. Deskew turns rectangles into polygons. Pad masks by several pixels, redact at line level, union overlaps, and dilate for descenders and antialiasing. Off-by-a-few-pixels errors leak glyph fragments.
Redaction is the wrong response to prompt injection. Distributed or reassembled payloads can survive masking. Use REDACT for PII/policy, and BLOCK for adversarial content. Run a post-redaction re-scan on anything you forward.
Audit stamp and API oracle. The stamp shouldn’t include matched content. The scan-image response, with exact coordinates, per-channel scores and forensic signatures, is an optimization oracle for black-box evasion. Quantize or coarsen scores for external callers and rate-limit, reserving detail for authenticated SOC roles.
Dashboard and audit store. Showing original-vs-redacted images means storing originals, which defeats redaction. Store hashes and redacted copies, encrypt at rest, and render untrusted images and OCR text in the dashboard as inert (escaped, sandboxed <img>) to avoid XSS.
Documents. If REDACT is extended to PDFs, drawing a rectangle leaves the text underneath. Use true content removal (apply_redactions) and check for incremental updates.
4. Pre-implementation changes

P0, change the design before coding:

Canonicalize, scan, forward the same bytes. Decode, composite, orient, re-encode to a sanitized PNG, and forward that. Fetch URLs once. This kills polyglots, trailing data, metadata and the TOCTOU.
Multi-view scanning: frames, alpha, rotations, contrast views, and VLM-matched downscales.
Fail-closed everywhere.
OCR/parse error, timeout, page or image budget exceeded, or encrypted file means FLAG or quarantine, never ALLOW. A payload on page 501 must not go unscanned.
MockOCRDriver must be unreachable in production; startup should refuse or run an explicit degraded mode.
Falling from EasyOCR to Tesseract on a crash is itself an evasion path, so run both for high-risk inputs.
Demote render mode 3 and LSB chi-square from Layer 1. Add the render-vs-text-layer diff oracle.
Calibrate CLIP thresholds empirically, add benign anchors, use tiling, and keep semantic margin as a corroboration-only channel.
Sandbox the parsers.
Parse in a separate process with no network and with CPU/memory limits and timeouts.
Set pixel-count and decompression caps. The 32MB stream cap doesn’t bound pixels.
Add ZIP/XML bomb limits with defusedxml and lxml resolve_entities=False.
Run MuPDF and Pillow out-of-process, since they parse hostile input in your security gateway.
Redaction: rebuild from pixels, strip metadata, pad, re-scan, BLOCK on injection.

P1: per-signal-class consensus with calibrated probabilities; QR/barcode and metadata channels; multi-parser extraction; CPU-bounded OCR worker pool with per-tenant quotas and content-hash caching; score coarsening on the external API.

P2: a written threat model that names the downstream consumer (raw image to a VLM, or text only) and attacker knowledge (white-box or black-box); shadow-mode rollout.

Suggested test corpus before shipping: typographic/overlay attacks, near-background and per-channel text, rotated/vertical text, scaling-attack samples, multi-frame and alpha tricks, glyph-remapped PDFs, and the benign side (scanned receipts, SDS sheets with GHS pictograms, dark IDE screenshots, branded slides with watermarks, OCR’d PDFs).

Happy to turn the P0 list into concrete module boundaries for core/vision/ or revise a specific plan doc.


Create a doc





just now