# 03 — SRM Filter Bank & Steganography Engine

**Module:** `core/vision/srm/`  
**Purpose:** Detect imperceptible high-frequency adversarial perturbations (PGD/FGSM visual jailbreaks) and LSB spatial steganography while guaranteeing zero false alarms on textured enterprise documents.

---

## 1. Threat Vectors & The High-Frequency Paradox

Adversarial vision attacks operate across two distinct modalities:
1. **Adversarial Perturbations (FGSM / PGD / Patch Attacks):** High-frequency gradient noise added to pixels ($L_\infty$ or $L_2$ bounded). While imperceptible to humans, the noise shifts the latent visual embeddings produced by multimodal LLMs (e.g. CLIP/LLaVA) to force compliance with unauthorized instructions.
2. **LSB Spatial Steganography:** Modifying the least significant bit of pixel values to conceal binary payloads, URLs, or shellcode inside innocuous images.

### The Core Engineering Challenge:
Naive frequency filters (like simple high-pass filters or Laplacian variance) fail catastrophically in enterprise gateways. A dark-mode code screenshot, a dense financial ledger, or a scanned paper receipt exhibits massive high-frequency energy due to text glyphs and gridlines. A naive high-pass filter would flag every legitimate business invoice as an attack.

Sentinel solves this by evaluating **spatial distribution and content correlation**, not aggregate energy.

---

## 2. Spatial Rich Model (SRM) Filter Bank

Sentinel implements a fixed, non-trainable PyTorch `nn.Conv2d` layer initialized with a curated set of **10 Spatial Rich Model (SRM) residual kernels** derived from steganalysis literature (Kodovsky & Fridrich):

$$\mathbf{R}_k = \text{quantize}\left( \mathbf{I} * \mathbf{K}_k, \; T=3 \right)$$

```
Kernel 1-3 (1st Order 3×3):
[ 0  0  0]     [ 0 -1  0]     [-1  0  0]
[-1  1  0]     [ 0  1  0]     [ 0  1  0]
[ 0  0  0]     [ 0  0  0]     [ 0  0  0]
(Horizontal)    (Vertical)     (Diagonal)

Kernel 4-5 (2nd Order Laplacian 3×3):
[ 0  1  0]     [ 1 -2  1]
[ 1 -4  1]     [-2  4 -2]
[ 0  1  0]     [ 1 -2  1]

Kernel 6 (Classic KV 5×5 Steganalysis Kernel):
[-1  2 -2  2 -1]
[ 2 -6  8 -6  2]
[-2  8 -12 8 -2]
[ 2 -6  8 -6  2]
[-1  2 -2  2 -1]

Kernel 7-8 (Square 3×3 and 5×5 Edge Inhibitors)
Kernel 9-10 (Corner & Cross-Difference Filters)
```

### Quantize-and-Truncate Invariant:
Residual maps are clipped to $[-T, T]$ where $T = 3.0$ and quantized to integer bins. This standard steganalysis operation strips content-dependent magnitude variations while preserving the fine statistical moments of high-frequency noise.

---

## 3. The Two Deterministic Discriminators

To distinguish natural enterprise text from adversarial perturbations, Sentinel deploys two complementary signals:

```
                  INPUT IMAGE (I)
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
   [Content Sobel                    [SRM Fixed
     Gradient G]                   Conv2d Residuals R]
        │                                 │
        └────────────────┬────────────────┘
                         ▼
        ┌───────────────────────────────────────────┐
        │       1. Edge-Residual Correlation        │
        │ • Cross-correlates G and |R|              │
        │ • High correlation = Natural Text         │
        │ • Low correlation  = Adversarial Noise    │
        └────────────────┬──────────────────────────┘
                         │
                         ▼
        ┌───────────────────────────────────────────┐
        │       2. Flat-Region Residual Leakage     │
        │ • Masks regions where G < Threshold       │
        │ • Measures residual variance in flat areas│
        │ • Natural docs: 0.0 residual in margins   │
        │ • PGD attacks: high residual leakage      │
        └───────────────────────────────────────────┘
```

### A. Edge-Residual Correlation ($C_{\text{edge}}$):
* In benign documents, high-frequency energy is strictly co-located with character glyphs and table borders. The Pearson correlation between the Sobel gradient magnitude $\mathbf{G}$ and the SRM residual magnitude $|\mathbf{R}|$ is high:
  $$C_{\text{edge}} = \frac{\sum (G_i - \bar{G})(|R_i| - |\bar{R}|)}{\sqrt{\sum (G_i - \bar{G})^2 \sum (|R_i| - |\bar{R}|)^2}} \ge 0.65$$
* In PGD/FGSM attacks, adversarial noise is applied near-globally across the entire canvas, regardless of what is underneath. As a result, $C_{\text{edge}}$ drops sharply ($C_{\text{edge}} < 0.35$).

### B. Flat-Region Residual Leakage ($L_{\text{flat}}$):
* A code screenshot or invoice has clean margins and whitespace between lines.
* Sentinel constructs a binary flat mask: $\mathbf{M}_{\text{flat}} = (\mathbf{G} < \tau_{\text{grad}})$.
* It measures the local residual variance strictly inside $\mathbf{M}_{\text{flat}}$:
  $$L_{\text{flat}} = \frac{1}{|\mathbf{M}_{\text{flat}}|} \sum_{i \in \mathbf{M}_{\text{flat}}} |R_i|^2$$
* In benign enterprise traffic: $L_{\text{flat}} \approx 0.0$ (whitespace is truly flat).
* In PGD/FGSM attacks: $L_{\text{flat}}$ spikes dramatically because the adversarial optimization function has no visual content to hide behind in empty margins.

---

## 4. LSB Bit-Plane Chi-Square Steganalysis

For spatial LSB steganography, Sentinel implements the **Westfeld & Pfitzmann $\chi^2$ Test** as an independent, sub-millisecond module (`core/vision/srm/lsb_detector.py`):

1. **Pairs of Values (PoVs):**
   In natural uncompressed images, adjacent pixel values ($2k$ and $2k+1$) have distinct frequencies based on scene lighting.
2. **Steganographic Effect:**
   Sequential or pseudo-random LSB overwriting equalizes the occurrence counts of $2k$ and $2k+1$.
3. **Statistical Test:**
   Sentinel partitions pixel values into 128 PoVs and calculates the chi-square statistic:
   $$\chi^2 = \sum_{k=0}^{127} \frac{\left( n_{2k} - n_{2k}^* \right)^2}{n_{2k}^*}, \quad \text{where } n_{2k}^* = \frac{n_{2k} + n_{2k+1}}{2}$$
   The resulting $p$-value indicates whether the LSB bit plane exhibits artificial equalization.
4. **Policy Enforcement:**
   A high-confidence chi-square violation ($p > 0.999$ across $> 5000$ PoVs) is treated as an independent **Layer-1 Deterministic Oracle**, triggering an immediate `BLOCK`.

