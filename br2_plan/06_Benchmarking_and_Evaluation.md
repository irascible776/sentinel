# Module 6: Benchmarking & Academic Evaluation Pipeline
**Developer 1 (Rohit) | Branch: `br2` | File: `tests/benchmark_detection.py`**

---

## 1. Objective & Academic Significance

For DTU project evaluations and the B.Tech Minor Project dissertation, qualitative claims are insufficient. Dr. Akshay Mool and external examiners require quantitative, scientifically validated benchmarks proving the effectiveness of the Multi-Agent Defense Architecture over a single detector.

Rohit will provide an automated benchmarking harness measuring:
1. **Classification Accuracy, Precision, Recall, and F1-Score** across balanced datasets.
2. **Sub-Agent Latency Overhead** (proving real-time feasibility without degrading user experience).
3. **Ablation Study (Ensemble vs. Single-Detector):** Proving that combining Pattern, Semantic, and Behavioral agents produces lower False Positive Rates (FPR) than either regex or transformer alone.

---

## 2. Evaluation Metrics Defined

$$\text{Precision} = \frac{TP}{TP + FP} \quad (\text{Minimizing false alarms on legitimate users})$$

$$\text{Recall} = \frac{TP}{TP + FN} \quad (\text{Catching all adversarial attacks})$$

$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

$$\text{Latency Overhead} = T_{\text{judge}} = T_{\text{pattern}} + T_{\text{semantic}} + T_{\text{behavioral}}$$

---

## 3. Benchmark Dataset Strategy

Rohit will assemble a curated benchmark suite in `tests/samples/benchmark_dataset.json` containing 200 labeled samples:
* **100 Benign Prompts (Class 0):** Customer service queries, coding questions, creative writing, academic queries, and innocent questions containing words like "prompt" or "rule" (testing for false positive resistance).
* **100 Adversarial Prompts (Class 1):** Direct instruction overrides, DAN 11.0 personas, fictional roleplays, Base64 obfuscations, and multi-turn extraction prompts from benchmark datasets (`deepset/prompt-injections`, `JailbreakBench`).

---

## 4. Benchmark Harness Design (`tests/benchmark_detection.py`)

```python
"""
Developer 1 (Rohit) - Academic Evaluation & Benchmarking Script
Generates Confusion Matrix, Precision, Recall, F1, and Latency breakdown.
"""
import time
import json
from core.detection.judge import JudgeAgent

def run_benchmark(dataset_path: str = "tests/samples/benchmark_dataset.json"):
    judge = JudgeAgent()
    with open(dataset_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    tp = fp = tn = fn = 0
    latencies = []

    for item in samples:
        prompt = item["prompt"]
        expected_attack = item["is_attack"] # True or False

        t0 = time.perf_counter()
        verdict = judge.evaluate(prompt, session_id="benchmark")
        latencies.append((time.perf_counter() - t0) * 1000)

        predicted_attack = verdict["decision"] in ["BLOCK", "FLAG"]

        if expected_attack and predicted_attack:
            tp += 1
        elif not expected_attack and predicted_attack:
            fp += 1
        elif not expected_attack and not predicted_attack:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    avg_latency = sum(latencies) / len(latencies)

    print("=" * 50)
    print("AI SECURITY GATEWAY — DETECTION BENCHMARK REPORT")
    print("=" * 50)
    print(f"Total Evaluated: {len(samples)}")
    print(f"True Positives: {tp} | False Positives: {fp}")
    print(f"True Negatives: {tn} | False Negatives: {fn}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"Average Latency: {avg_latency:.2f} ms")
    print("=" * 50)

if __name__ == "__main__":
    run_benchmark()
```

---

## 5. Expected Performance Targets for Dissertation

| Architecture Configuration | Precision | Recall | F1-Score | Latency Overhead |
|---|---|---|---|---|
| Pattern Hunter (Regex Only) | 0.94 | 0.62 | 0.75 | < 2 ms |
| Semantic Analyst (DeBERTa Only) | 0.88 | 0.91 | 0.89 | ~ 24 ms |
| **Multi-Agent Ensemble (Our System)** | **0.96** | **0.94** | **0.95** | **~ 26 ms** |
