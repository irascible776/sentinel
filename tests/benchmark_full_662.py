"""
Full Dataset Academic & Industry Benchmark: deepset/prompt-injections (662 samples)
Evaluates Sentinel's Multi-Agent Detection & Consensus Engine across the entire
public benchmark dataset (263 adversarial attacks, 399 benign prompts).
"""

import os
import sys
import json
import time
import requests
from typing import Dict, List, Any

# Ensure project root is in sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core.detection.judge import JudgeAgent

DATASET_OUT = os.path.join(REPO_ROOT, "tests", "samples", "benchmark_deepset_all_662.json")
REPORT_OUT = os.path.join(REPO_ROOT, "tests", "samples", "benchmark_report_deepset_all_662.json")


def fetch_full_dataset() -> List[Dict[str, Any]]:
    """
    Downloads every single sample from both test (116) and train (546) splits of
    deepset/prompt-injections from HuggingFace (total 662 samples).
    """
    if os.path.exists(DATASET_OUT):
        print(f"Loading cached full dataset from {DATASET_OUT}...")
        with open(DATASET_OUT, "r", encoding="utf-8") as f:
            return json.load(f)

    print("Fetching all 662 samples from 'deepset/prompt-injections'...")
    all_samples = []

    # 1. Fetch test split (116 rows)
    for offset in [0, 100]:
        url = f"https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections&config=default&split=test&offset={offset}&limit=100"
        try:
            res = requests.get(url, timeout=15).json()
            for r in res.get("rows", []):
                all_samples.append({
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
                all_samples.append({
                    "prompt": r["row"]["text"],
                    "is_attack": bool(r["row"]["label"] == 1),
                    "split": "train"
                })
        except Exception as e:
            print(f"Error fetching train offset {offset}: {e}")

    os.makedirs(os.path.dirname(DATASET_OUT), exist_ok=True)
    with open(DATASET_OUT, "w", encoding="utf-8") as f:
        json.dump(all_samples, f, indent=2)

    attacks = sum(1 for s in all_samples if s["is_attack"])
    benign = len(all_samples) - attacks
    print(f"Successfully saved all {len(all_samples)} samples ({attacks} attacks, {benign} benign) to {DATASET_OUT}.\n")
    return all_samples


def run_full_benchmark(dataset: List[Dict[str, Any]]):
    attacks_total = sum(1 for s in dataset if s["is_attack"])
    benign_total = len(dataset) - attacks_total

    print("=" * 72)
    print("   SENTINEL AI SECURITY GATEWAY — FULL PUBLIC DATASET BENCHMARK")
    print("   Dataset: deepset/prompt-injections (Full 662 Samples)")
    print(f"   Composition: {attacks_total} Adversarial Attacks | {benign_total} Benign Prompts")
    print("=" * 72)

    judge = JudgeAgent()
    # Warmup pipeline
    judge.evaluate("Warmup prompt for transformer pipeline.")

    tp = 0  # Attack correctly caught (BLOCK or FLAG)
    fp = 0  # Clean prompt falsely flagged/blocked
    tn = 0  # Clean prompt correctly allowed
    fn = 0  # Attack missed (allowed)

    latencies: List[float] = []
    t_start_total = time.time()

    for idx, item in enumerate(dataset, 1):
        prompt = item["prompt"]
        expected_attack = item["is_attack"]

        t0 = time.perf_counter()
        verdict = judge.evaluate(prompt, session_id=f"full-bench-{idx}")
        latency = (time.perf_counter() - t0) * 1000.0
        latencies.append(latency)

        decision = verdict.get("decision", "ALLOW")
        predicted_attack = decision in ["BLOCK", "FLAG"]

        if expected_attack and predicted_attack:
            tp += 1
        elif not expected_attack and not predicted_attack:
            tn += 1
        elif not expected_attack and predicted_attack:
            fp += 1
        else:
            fn += 1

        if idx % 50 == 0 or idx == len(dataset):
            print(f"[{idx:03d}/{len(dataset)}] Progress | TP: {tp}/{attacks_total} | TN: {tn}/{benign_total} | FP: {fp} | FN: {fn} | Latency: {latency:.1f}ms", flush=True)

    total_time_sec = time.time() - t_start_total

    # Metric computations
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(dataset) if dataset else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    print("\n" + "=" * 72)
    print("                 FULL DATASET EVALUATION SUMMARY (662 SAMPLES)")
    print("=" * 72)
    print(f"Total Evaluated Samples:     {len(dataset)}")
    print(f"Total Execution Time:        {total_time_sec:.2f} seconds ({total_time_sec/60:.2f} minutes)")
    print(f"True Positives (TP):         {tp} / {attacks_total}")
    print(f"True Negatives (TN):         {tn} / {benign_total}")
    print(f"False Positives (FP):        {fp}")
    print(f"False Negatives (FN):        {fn}")
    print("-" * 72)
    print(f"Overall Accuracy:            {accuracy * 100:.2f}%")
    print(f"Precision:                   {precision * 100:.2f}%")
    print(f"Recall (Sensitivity):        {recall * 100:.2f}%")
    print(f"F1-Score:                    {f1:.4f}")
    print(f"False Positive Rate (FPR):   {fpr * 100:.2f}%")
    print(f"Average Latency per Prompt:  {avg_latency:.2f} ms")
    print("=" * 72)

    report = {
        "dataset": "deepset/prompt-injections (full)",
        "total_samples": len(dataset),
        "attacks_count": attacks_total,
        "benign_count": benign_total,
        "accuracy_pct": round(accuracy * 100, 2),
        "precision_pct": round(precision * 100, 2),
        "recall_pct": round(recall * 100, 2),
        "f1_score": round(f1, 4),
        "false_positive_rate_pct": round(fpr * 100, 2),
        "avg_latency_ms": round(avg_latency, 2),
        "execution_time_sec": round(total_time_sec, 2),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn
    }

    with open(REPORT_OUT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Full benchmark report saved to {REPORT_OUT}\n")


if __name__ == "__main__":
    dataset = fetch_full_dataset()
    run_full_benchmark(dataset)
