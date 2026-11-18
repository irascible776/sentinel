# 06 Algorithms & Data Structures Registry

This document lists every algorithm, data structure, and mathematical formulation implemented in the Sentinel repository, with exact source references, complexity analysis, and engineering rationale.

---

## 1. Master Algorithms & Data Structures Table

| Algorithm / Data Structure | File:Line | Purpose | Time Complexity | Space Complexity | Engineering Rationale / Code Justification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Ingress Text Normalization Pipeline** | `sentinel/core/detection/normalizer.py:47-82` | Strips invisible glyphs, normalizes Unicode NFKC, transliterates Cyrillic/Greek homoglyphs, collapses repetitions, expands typos | $O(L)$ where $L$ is string length | $O(L)$ output string | Strips adversarial homoglyph and zero-width bypasses before regex and model evaluation without mutating the original user payload [VERIFIED sentinel/core/detection/normalizer.py:49-58] |
| **Compiled Regex Signature Scanner with Mtime Invalidation** | `sentinel/core/detection/pattern_hunter.py:22-58, 120-141` | Compiles JSON signatures into regex list and scans text targets | $O(R \cdot L)$ where $R$ is rule count, $L$ is text length | $O(R)$ compiled patterns in memory | Dynamic hot-reloading allows real-time threat feed rule ingestion without locking or server restarts [VERIFIED sentinel/core/detection/pattern_hunter.py:23-53] |
| **Base64 Auto-Padding & Obfuscation Extraction** | `sentinel/core/detection/pattern_hunter.py:59-86` | Extracts candidate Base64 strings $\ge 16$ chars, auto-pads (`len % 4`), decodes UTF-8 | $O(L)$ regex search and decoding | $O(L)$ decoded strings | Adversarial prompts frequently embed jailbreaks inside Base64 blobs to defeat basic keyword filters [VERIFIED sentinel/core/detection/pattern_hunter.py:61-63] |
| **Exponential Temporal Decay & Sliding Window Session Memory** | `sentinel/core/detection/behavioral_profiler.py:28-58, 123-138` | Tracks per-session risk history with exponential decay $\tau = 180.0\text{ s}$ and 10-minute sliding window | $O(K)$ where $K$ is session record count | $O(S \cdot K)$ capped at 10,000 sessions with 20% oldest eviction | Balances immediate detection of multi-turn boundary probing against gradual forgiveness of past false alarms [VERIFIED sentinel/core/detection/behavioral_profiler.py:123-138] |
| **Probing Escalation & Velocity Penalties** | `sentinel/core/detection/behavioral_profiler.py:112-154` | Identifies strictly increasing risk across 3 interactions and rapid fuzzing ($>15\text{ RPM}$) | $O(1)$ over last 3 turns | $O(1)$ | Flags automated prompt generation and gradual jailbreak fuzzing tools while capping behavioral score at 65.0 to avoid isolated false blocks [VERIFIED sentinel/core/detection/behavioral_profiler.py:144-153] |
| **Cryptographic Nonce Delimitation & Tag Neutralization** | `sentinel/core/detection/stage2_arbiter.py:221-227, 315-325` | Wraps untrusted classification payloads inside `<input_{nonce}>` with 16-hex nonce and neutralizes closing tags | $O(L)$ regex replace | $O(L)$ formatted string | Prevents delimiter injection / prompt breakout attacks targeting the safety arbiter itself [VERIFIED sentinel/core/detection/stage2_arbiter.py:314-325] |
| **TF-IDF N-Gram Pattern Extraction & Clustering** | `sentinel/core/security_vectors/threat_feed.py:52-80` | Extracts recurring 2-gram to 4-gram phrases across blocked prompts | $O(N \cdot L)$ where $N$ is sample count | $O(V)$ vocabulary size (max 50 features) | Enables closed-loop autonomous signature generation from live attack traffic without human labeling [VERIFIED sentinel/core/security_vectors/threat_feed.py:52-64] |
| **Overlapping Sliding Window Text Chunking** | `sentinel/core/security_vectors/rag_scanner.py:51-75` | Splits knowledge documents into 500-char chunks with 50-char overlap | $O(L)$ string slicing | $O(L)$ list of chunk strings | Prevents split-token evasion where an attacker divides a jailbreak command across document chunk boundaries [VERIFIED sentinel/core/security_vectors/rag_scanner.py:53-55] |
| **AST Visitor Taint Flow Analysis (Python)** | `sentinel/core/codesec/ast_parser.py:50-250; sentinel/core/gateway/ast_analyzer.py:65-215` | Traverses AST nodes, tracking data taint from untrusted sources to execution/exfiltration sinks | $O(V + E)$ AST nodes and edges | $O(N)$ symbol table and call graph | Static validation of code safety guarantees detection of command injection and exfiltration even if prompts evade natural language filters [VERIFIED sentinel/core/gateway/ast_analyzer.py:18-21] |
| **Shannon String Entropy Calculation** | `sentinel/core/codesec/secret_scanner.py:57-67; sentinel/core/malware/entropy.py:15-50` | Computes $H(X) = -\sum p(x) \log_2 p(x)$ in bits per character/byte | $O(L)$ character count | $O(\Sigma)$ symbol frequency table | High entropy ($H \ge 3.8$ in code, $H \ge 7.2$ in binaries) identifies cryptographic keys and packed/encrypted malware sections [VERIFIED sentinel/core/codesec/config.py:56; sentinel/core/malware/config.py:26] |
| **Westfeld & Pfitzmann Chi-Square Test on PoVs** | `sentinel/core/vision/srm/lsb_detector.py:20-85` | Tests Pairs of Values ($2k, 2k+1$) across pixel histograms for LSB steganography | $O(H \cdot W)$ image traversal | $O(1)$ 256-bin histogram | Least-significant-bit embedding equalizes adjacent frequency counts; $\chi^2$ survival function $p > 0.95$ detects hidden payloads [VERIFIED sentinel/core/vision/srm/lsb_detector.py:22-24] |
| **CIE L\*a\*b\* Euclidean Color Distance ($\Delta E$)** | `sentinel/core/vision/document/hidden_text_rules.py:22-65` | Converts sRGB to CIE L\*a\*b\* (D65) and calculates Euclidean distance $\Delta E$ | $O(1)$ per text-background check | $O(1)$ color coordinates | Human perceptual color difference threshold ($\Delta E \le 4.5$) catches invisible white-on-white text in PDFs and DOCX files [VERIFIED sentinel/core/vision/document/hidden_text_rules.py:56-60] |
| **TAP-Lite (Tree of Attacks with Pruning) Search** | `sentinel/core/redteam/search.py:45-285` | Beam search exploring attack mutations with beam width 3, branch factor 2, max depth 4 | $O(B \cdot K \cdot D)$ queries | $O(B \cdot K \cdot D)$ state records | Explores multi-turn attack strategies while pruning branches with token cosine similarity $< 0.50$ to retain semantic intent [VERIFIED sentinel/core/redteam/search.py:47-59] |
| **Windowed Token Longest Common Subsequence (LCS)** | `sentinel/core/redteam/judge.py:42-65` | Sliding window SequenceMatcher calculating token overlap ratio $\ge 0.70$ | $O(W \cdot N)$ where $W$ is reference words | $O(W)$ window buffer | Detects system prompt extractions embedded within long conversational text responses [VERIFIED sentinel/core/redteam/judge.py:42-46] |
| **MalConv 1D Gated Convolutions** | `sentinel/core/malware/malconv.py:18-57` | Gated 1D convolution with kernel=500, stride=500, adaptive max-pooling | $O(L / \text{stride})$ operations | $O(L \cdot \text{embed\_dim})$ tensor | Extracts structural macro-patterns from raw binary files up to 2 MB without disassembling or executing the binary [VERIFIED sentinel/core/malware/malconv.py:20-23] |
| **Spatial Rich Model (SRM) 10-Kernel Filter Bank** | `sentinel/core/vision/srm/kernels.py:12-186` | 10 directional 5x5 high-pass residual filters with $[-T, T]$ clipping | $O(K \cdot H \cdot W)$ convolutions | $O(K \cdot H \cdot W)$ feature map | Isolates high-frequency residual noise patterns for adversarial PGD perturbation and steganography detection [VERIFIED sentinel/core/vision/srm/kernels.py:158-161] |
| **Mutex-Guarded LRU Tool Argument Cache** | `sentinel/core/detection/tool_guardrail.py:35-37, 70-85` | `OrderedDict` with `threading.Lock()` storing up to 1,024 argument hashes | $O(1)$ cache hit / eviction | $O(C)$ where $C=1024$ entries | Avoids redundant AST traversal and ML inference on recurring identical agent tool parameters [VERIFIED sentinel/core/detection/tool_guardrail.py:35-36, 75-80] |
| **Data-Flow Graph (DFG) Constrained Attention** | `sentinel/core/codesec/codebert_head.py:27-64` | Multi-head self-attention with additive $-10^9$ mask along non-dataflow edges | $O(B \cdot H \cdot L^2)$ matrix operations | $O(B \cdot L^2)$ attention mask | Enforces that attention weights flow strictly along def-use chains in code tokens, matching GraphCodeBERT semantics [VERIFIED sentinel/core/codesec/codebert_head.py:28-31] |

---

## 2. Mathematical Formulations in Code

### 1. Behavioral Temporal Decay
$$\text{decay\_factor} = e^{-\frac{\Delta t}{180.0}}$$
[VERIFIED sentinel/core/detection/behavioral_profiler.py:127]

### 2. Master Judge Composite Ingress Risk
$$\text{blended\_risk} = 0.20 \times \text{pattern} + 0.35 \times \text{semantic} + 0.30 \times \text{intent} + 0.15 \times \text{behavioral}$$
$$\text{composite\_risk} = \max(\text{blended\_risk}, \text{intent} \times 0.85)$$
[VERIFIED sentinel/core/detection/judge.py:169-176]

### 3. Shannon Entropy
$$H(S) = -\sum_{i=1}^{k} \frac{c_i}{|S|} \log_2 \left(\frac{c_i}{|S|}\right)$$
[VERIFIED sentinel/core/codesec/secret_scanner.py:57-67; sentinel/core/malware/entropy.py:25-45]

### 4. CIE L\*a\*b\* Color Difference ($\Delta E_{76}$)
$$\Delta E = \sqrt{(L_1^* - L_2^*)^2 + (a_1^* - a_2^*)^2 + (b_1^* - b_2^*)^2}$$
[VERIFIED sentinel/core/vision/document/hidden_text_rules.py:56-65]

### 5. Westfeld & Pfitzmann Chi-Square on Pairs of Values (PoVs)
$$\chi^2 = \sum_{k=0}^{127} \frac{(h_{2k} - h_{2k+1})^2}{2(h_{2k} + h_{2k+1})}$$
$$p = \text{sf}(\chi^2, \text{df}=127)$$
[VERIFIED sentinel/core/vision/srm/lsb_detector.py:65-80]

### 6. Code Security Tier 3 Calibrated Ensemble
$$\text{Risk}_{\text{code}} = 0.35 \times \text{AST} + 0.45 \times \text{CodeBERT} + 0.20 \times \text{Secrets}$$
[VERIFIED sentinel/core/codesec/config.py:45-47; sentinel/core/codesec/judge.py:115-135]
