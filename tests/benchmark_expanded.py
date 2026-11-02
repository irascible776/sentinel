"""
Expanded Academic & Industry Benchmark Script: deepset/prompt-injections
Downloads a balanced, representative evaluation set of 300 samples from Hugging Face
and benchmarks Sentinel's Multi-Agent Detection & Consensus Engine.
"""

import os
import sys
import json
import time
import random
import requests
from typing import Dict, List, Any

# Ensure project root is in sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core.detection.judge import JudgeAgent

DATASET_OUT = os.path.join(REPO_ROOT, "tests", "samples", "benchmark_deepset_300.json")


def fetch_deepset_dataset(target_samples: int = 300) -> List[Dict[str, Any]]:
    """
    Downloads test and train splits of deepset/prompt-injections from HuggingFace
    and creates a balanced 50/50 dataset of target_samples.
    """
    if os.path.exists(DATASET_OUT):
        print(f"Loading cached dataset from {DATASET_OUT}...")
        with open(DATASET_OUT, "r", encoding="utf-8") as f:
            return json.load(f)

    print("Fetching 'deepset/prompt-injections' from Hugging Face datasets server...")
    raw_samples = []

    # 1. Fetch test split (116 rows)
    for offset in [0, 100]:
        url = f"https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections&config=default&split=test&offset={offset}&limit=100"
        try:
            res = requests.get(url, timeout=15).json()
            for r in res.get("rows", []):
                raw_samples.append({
                    "prompt": r["row"]["text"],
                    "is_attack": bool(r["row"]["label"] == 1),
                    "split": "test"
                })
        except Exception as e:
            print(f"Error fetching test offset {offset}: {e}")

    # 2. Fetch train split (546 rows)
    for offset in [0, 100, 200, 300, 400, 500]:
        url = f"https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections&config=default&split=train&offset={offset}&limit=100"
        try:
            res = requests.get(url, timeout=15).json()
            for r in res.get("rows", []):
                raw_samples.append({
                    "prompt": r["row"]["text"],
                    "is_attack": bool(r["row"]["label"] == 1),
                    "split": "train"
                })
        except Exception as e:
            print(f"Error fetching train offset {offset}: {e}")

    attacks = [s for s in raw_samples if s["is_attack"]]
    benign = [s for s in raw_samples if not s["is_attack"]]

    print(f"Fetched {len(raw_samples)} raw rows ({len(attacks)} attacks, {len(benign)} benign).")

    # Sample balanced set (150 attacks, 150 benign)
    random.seed(42)
    half = target_samples // 2
    selected_attacks = random.sample(attacks, min(half, len(attacks)))
    selected_benign = random.sample(benign, min(half, len(benign)))

    dataset = selected_attacks + selected_benign
    random.shuffle(dataset)

    os.makedirs(os.path.dirname(DATASET_OUT), exist_ok=True)
    with open(DATASET_OUT, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    print(f"Saved balanced dataset of {len(dataset)} samples to {DATASET_OUT}.\n")
    return dataset


def run_benchmark(dataset: List[Dict[str, Any]]):
    print("=" * 70)
    print("   SENTINEL AI SECURITY GATEWAY — EXPANDED DATASET BENCHMARK")
    print("   Public Dataset: deepset/prompt-injections (Hugging Face)")
    print(f"   Sample Size: {len(dataset)} balanced prompts (50% Attack, 50% Benign)")
    print("=" * 70)

    judge = JudgeAgent()
    # Warmup
    judge.evaluate("Warmup prompt for transformer pipeline.")

    tp = 0  # Attack correctly blocked/flagged
    fp = 0  # Clean prompt falsely blocked/flagged
    tn = 0  # Clean prompt correctly allowed
    fn = 0  # Attack missed (allowed)

    latencies: List[float] = []

    t_start_total = time.time()

    for idx, item in enumerate(dataset, 1):
        prompt = item["prompt"]
        expected_attack = item["is_attack"]

        t0 = time.perf_counter()
        verdict = judge.evaluate(prompt, session_id=f"exp-bench-{idx}")
        latency = (time.perf_counter() - t0) * 1000.0
        latencies.append(latency)

        decision = verdict.get("decision", "ALLOW")
        predicted_attack = decision in ["BLOCK", "FLAG"]

        if expected_attack and predicted_attack:
            tp += 1
            status = "TP [HIT]"
        elif not expected_attack and not predicted_attack:
            tn += 1
            status = "TN [CLEAN]"
        elif not expected_attack and predicted_attack:
            fp += 1
            status = "FP [FALSE ALARM]"
        else:
            fn += 1
            status = "FN [MISS]"

        if idx % 25 == 0 or idx == len(dataset):
            print(f"Progress: [{idx:03d}/{len(dataset)}] | TP: {tp} | TN: {tn} | FP: {fp} | FN: {fn} | Last Latency: {latency:.1f}ms")

    total_time_sec = time.time() - t_start_total

    # Metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(dataset) if dataset else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    print("\n" + "=" * 70)
    print("                      EXPANDED BENCHMARK RESULTS")
    print("=" * 70)
    print(f"Total Evaluated Samples:     {len(dataset)}")
    print(f"Total Execution Time:        {total_time_sec:.2f} seconds")
    print(f"True Positives (TP):         {tp} / 150")
    print(f"True Negatives (TN):         {tn} / 150")
    print(f"False Positives (FP):        {fp}")
    print(f"False Negatives (FN):        {fn}")
    print("-" * 70)
    print(f"Classification Accuracy:     {accuracy * 100:.2f}%")
    print(f"Precision:                   {precision * 100:.2f}%")
    print(f"Recall (Sensitivity):        {recall * 100:.2f}%")
    print(f"F1-Score:                    {f1:.4f}")
    print(f"False Positive Rate (FPR):   {fpr * 100:.2f}%")
    print(f"Average Latency per Prompt:  {avg_latency:.2f} ms")
    print("=" * 70)

    # Save summary report
    report = {
        "dataset": "deepset/prompt-injections",
        "sample_size": len(dataset),
        "accuracy_pct": round(accuracy * 100, 2),
        "precision_pct": round(precision * 100, 2),
        "recall_pct": round(recall * 100, 2),
        "f1_score": round(f1, 4),
        "false_positive_rate_pct": round(fpr * 100, 2),
        "avg_latency_ms": round(avg_latency, 2),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn
    }

    report_path = os.path.join(REPO_ROOT, "tests", "samples", "benchmark_report_deepset.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Report saved to {report_path}\n")


if __name__ == "__main__":
    data = fetch_deepset_dataset(target_samples=300)
    run_benchmark(data)
