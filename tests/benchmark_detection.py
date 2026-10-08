"""
Developer 1 (Rohit Verma) — Academic Evaluation & Benchmarking Script
Generates Confusion Matrix, Precision, Recall, F1-Score, and sub-agent Latency metrics.
Output format tailored for DTU Project-1 (IT401) Minor Project dissertation & presentation.
"""

import time
import json
import os
import sys

# Ensure project root is in sys.path when invoked directly:
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from typing import Dict, List, Any
from core.detection.judge import JudgeAgent

def run_benchmark(dataset_path: str = "tests/samples/benchmark_dataset.json") -> Dict[str, Any]:
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        return {}

    with open(dataset_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    judge = JudgeAgent()

    tp = 0  # True Positive: Attack correctly blocked or flagged
    fp = 0  # False Positive: Clean prompt falsely blocked or flagged
    tn = 0  # True Negative: Clean prompt correctly allowed
    fn = 0  # False Negative: Attack missed (allowed)

    latencies_overall: List[float] = []
    latencies_pattern: List[float] = []
    latencies_semantic: List[float] = []
    latencies_behavioral: List[float] = []

    print("\n" + "=" * 65)
    print("   AI SECURITY GATEWAY — MULTI-AGENT DETECTION BENCHMARK")
    print("   B.Tech Minor Project (IT401) | Group 138 | DTU IT Dept")
    print("=" * 65)
    print(f"Loaded {len(samples)} benchmark evaluation samples...\n")

    for idx, item in enumerate(samples, 1):
        prompt = item["prompt"]
        expected_attack = bool(item["is_attack"])

        t0 = time.perf_counter()
        verdict = judge.evaluate(prompt, session_id=f"bench-{idx}")
        total_time_ms = (time.perf_counter() - t0) * 1000.0

        latencies_overall.append(total_time_ms)
        predicted_attack = verdict["decision"] in ["BLOCK", "FLAG"]

        if expected_attack and predicted_attack:
            tp += 1
            status = "TP [CORRECT DETECT]"
        elif not expected_attack and not predicted_attack:
            tn += 1
            status = "TN [CLEAN ALLOW]"
        elif not expected_attack and predicted_attack:
            fp += 1
            status = "FP [FALSE ALARM]"
        else:
            fn += 1
            status = "FN [MISSED ATTACK]"

        snippet = (prompt[:45] + "...") if len(prompt) > 45 else prompt
        print(f"[{idx:02d}/{len(samples)}] {status:<18} | Risk: {verdict['risk_score']:>5.1f} | Dec: {verdict['decision']:<5} | \"{snippet}\"")

    # Metric computations
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(samples) if samples else 0.0
    avg_latency = sum(latencies_overall) / len(latencies_overall) if latencies_overall else 0.0

    print("\n" + "=" * 65)
    print("                      EVALUATION SUMMARY")
    print("=" * 65)
    print(f"Total Evaluated Samples:     {len(samples)}")
    print(f"True Positives (TP):         {tp}")
    print(f"True Negatives (TN):         {tn}")
    print(f"False Positives (FP):        {fp}")
    print(f"False Negatives (FN):        {fn}")
    print("-" * 65)
    print(f"Classification Accuracy:     {accuracy * 100:.2f}%")
    print(f"Precision:                   {precision:.4f} ({precision * 100:.1f}%)")
    print(f"Recall (Sensitivity):        {recall:.4f} ({recall * 100:.1f}%)")
    print(f"F1-Score:                    {f1:.4f}")
    print(f"Average Processing Latency:  {avg_latency:.2f} ms")
    print("=" * 65 + "\n")

    return {
        "total": len(samples),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "avg_latency_ms": avg_latency
    }

if __name__ == "__main__":
    run_benchmark()
