# Sentinel Metrics: Interview Study Guide

**Purpose:** Explain exactly how the Sentinel test and performance figures were produced, what they mean, what they do not mean, and how to discuss them honestly in a backend interview.

## 1. The 662-prompt benchmark

### What ran

The benchmark runner is `sentinel/tests/benchmark_full_662.py`. It loads the local `tests/samples/benchmark_deepset_all_662.json`, warms the `JudgeAgent` once, then calls `judge.evaluate(prompt, session_id=...)` once for each of 662 prompts. For scoring, a prediction is positive if the decision is `BLOCK` **or** `FLAG`; only `ALLOW` counts as a negative prediction. Each prompt gets a distinct session ID.

The dataset contains 263 attack-labeled and 399 benign-labeled examples. The dataset builder combines the public dataset's train and test splits. Describe this as a benchmark over the 662-row public corpus, not as a separate held-out test split. Training-data overlap was not established in this task.

The timer around each prompt uses `time.perf_counter()` and surrounds the `JudgeAgent.evaluate()` call. The reported average is therefore **detection-engine latency per sequential prompt**. It excludes HTTP request handling, network transfer, database logging, and time waiting for an upstream LLM response. The total-run timer starts after warm-up. The benchmark is sequential, so it does not measure concurrency or requests per second.

### Metric definitions

| Term | Meaning in this benchmark | Formula |
|---|---|---|
| TP | Attack-labeled prompt returned `BLOCK` or `FLAG` | — |
| FP | Benign-labeled prompt returned `BLOCK` or `FLAG` | — |
| TN | Benign-labeled prompt returned `ALLOW` | — |
| FN | Attack-labeled prompt returned `ALLOW` | — |
| Precision | Of the prompts flagged/blocked, fraction labeled attack | `TP / (TP + FP)` |
| Recall | Of the attack prompts, fraction flagged/blocked | `TP / (TP + FN)` |
| False-positive rate | Of benign prompts, fraction incorrectly flagged/blocked | `FP / (FP + TN)` |
| Accuracy | Fraction of all decisions matching labels | `(TP + TN) / N` |
| F1 | Harmonic mean of precision and recall | `2 × precision × recall / (precision + recall)` |

For the stored run: TP=107, FP=4, TN=395, FN=156. Thus precision=`107/111`=96.40%; recall=`107/263`=40.68%; FPR=`4/399`=1.00%; accuracy=`502/662`=75.83%; F1=0.5722. The low recall is material: 156 of the 263 attack examples were allowed by the measured decision rule. Avoid describing this result as “96.4% accurate” or implying that 96.4% of all attacks were caught.

### Stored result versus fresh CPU run

The stored report is the historical result used in the current CV. It remains a real recorded measurement. Its stored figures are 96.4% precision, 40.68% recall, 1.0% FPR, 75.83% accuracy, 0.5722 F1, and 678.02 ms mean judge latency.

A separate fresh run in this task evaluated the same 662 prompts using CPU-only PyTorch and local DeBERTa weights. The local GGUF path was configured, but `llama-cpp-python` was unavailable, so Stage 2 used its fallback. That run produced TP=104, FP=20, TN=379, FN=159; precision 83.87%, recall 39.54%, FPR 5.01%, accuracy 72.96%, F1 0.5375, mean latency 841.07 ms, median 720.76 ms, P95 1,566.66 ms, and maximum 3,801.07 ms. It took 556.80 s total.

These two runs use different runtime/device and arbiter conditions. If asked why they differ, explain that the fresh run lacked the configured local Stage 2 inference package and used the safe fallback; do not claim that it proves the detector regressed. To make a direct comparison, rerun the benchmark with the original backend, model, hardware, dependency versions, and decision configuration. The fresh run did not overwrite the stored JSON report.

## 2. PatternHunter-only diagnostic

`PatternHunter.scan()` was run separately on the same 662 prompts, with classification cutoffs of score `>=40` and `>=80`. This is an isolated regex/signature pass, not the final multi-agent judge. At `>=40`, precision was 47.06%, recall 6.08%, FPR 4.51%, accuracy 59.97%, and F1 0.1077. At `>=80`, precision was 100%, recall 1.90%, FPR 0%, accuracy 61.03%, and F1 0.0373.

Per-call wall time was measured with `time.perf_counter_ns()` around `hunter.scan(prompt)`, including its in-process normalization, base64 scan, regex checks, and rule-file mtime check. Mean was 0.4851 ms, median 0.3163 ms, P95 1.3355 ms, and maximum 13.4219 ms. This result shows why the pattern layer is only one signal in an ensemble. Do not use these standalone threshold results as the gateway's overall detection metrics.

## 3. Code-scan cache microbenchmark

The measured method was `CodeSecurityEngine.scan_code()` from `sentinel/core/codesec/engine.py`. Its cache is an in-memory LRU capped at 1,024 entries and keyed by SHA-256 over language and code. The benchmark ran 60 unique, short Python snippets as cache misses, then timed 2,000 repeated calls on one exact snippet after it was already cached. It measured the outer call using `time.perf_counter_ns()` to avoid the engine's internal latency field rounding cache-hit times to hundredths of a millisecond.

- Unique/uncached snippets: median 2.5728 ms, P95 5.2928 ms (n=60).
- Warm exact cache hits: median 0.0615 ms, P95 0.1243 ms (n=2,000).
- Ratio of medians: 2.5728 / 0.0615 = **41.9×**.
- The final result's `cached` flag was asserted true.

This is a local single-process microbenchmark on very small snippets. The repeat path still includes the method call, hash calculation, locking, LRU lookup, and copying the cached result. It does not measure a web request, concurrent load, database work, large code samples, or a cold process. A sound interview phrasing is “in a local microbenchmark, repeated identical snippets were 41.9× faster at the median”; avoid saying “the service is 41.9× faster” without that scope.

## 4. Canary exact-match microbenchmark

The benchmark exercised `CanaryEngine.check_leak(text, token)`. It generated a token, asserted that a roughly 260-character response containing that token returned `True`, and asserted that a 248-character clean response returned `False`. `timeit.repeat` ran nine batches of 100,000 calls for each case.

- Token present: median batch-average 0.000353 ms (0.353 µs) per check; batch range 0.000296–0.000547 ms.
- Token absent: median batch-average 0.000285 ms (0.285 µs) per check; batch range 0.000255–0.000341 ms.
- Each case included 900,000 calls total; both functional assertions passed.

This measures only an in-memory Python substring check. It excludes SSE parsing, network reads, chunk buffering, DLP, database writes, and scheduling. Say “the exact-token helper measured about 0.35 microseconds per hit in a local microbenchmark,” not “canary detection takes 0.35 microseconds end to end.”

## 5. Automated test results

The project context inventory records 171 tests across nine files. This task did not obtain a completed full-suite result.

- Syntax compilation passed: `python3 -m compileall -q core dashboard tests scripts`.
- Code security module excluding its three gateway API cases: 27 passed, 3 deselected, 17.22 s.
- Components, detection, malware unit tests, red-team unit tests, security vectors, tool guardrail unit tests, and vision unit tests excluding endpoint cases: 114 passed, 16 deselected, 146.33 s.
- Combined selected result: 141 passed, 19 endpoint cases deselected across those commands. The separate 11-test `tests/test_gateway.py` module was not run.

The first test environment lacked `pytest`; packages were installed only into `/tmp/sentinel-test-venv`. FastAPI also required `python-multipart` to register upload routes, so it was added only to that temporary environment. No project requirements file was edited.

The attempted full run stopped progressing at `test_gateway_api_scan_code_clean`. A focused faulthandler dump showed the calling thread waiting in Starlette `TestClient`/HTTPX, with the portal loop idle in selector wait. Repeating with Starlette 1.6 did not resolve it. A separate Uvicorn run did not finish application lifespan warm-up, so it never accepted the health request. These outcomes make the HTTP integration path **unverified in this environment**; they are not proof of an endpoint assertion failure.

## 6. Accurate interview answers

### “How did you measure detection quality?”

“I ran the judge sequentially over 662 labeled prompts from the public deepset prompt-injections corpus, counted `BLOCK` and `FLAG` as detections, and computed precision, recall, false-positive rate, accuracy, and F1 from the confusion matrix. The stored run reached 96.4% precision and 1.0% FPR, but recall was 40.7%, so the result reflects a low-false-alarm trade-off and still misses many attacks. The corpus builder combines train and test splits, so I present it as a public-corpus benchmark, not an independent held-out evaluation.”

### “What does the latency number cover?”

“The stored 678 ms is average sequential `JudgeAgent.evaluate()` time per prompt after model warm-up. It does not include HTTP, upstream model generation, logging, or load/concurrency effects. I separately measured a CPU/fallback configuration at 841 ms mean and 1.57 s P95, but that setup did not have the intended local Stage 2 package, so I keep it separate rather than treating it as comparable.”

### “How did you measure the cache speedup?”

“I timed 60 unique short snippets through the code scanner, then timed 2,000 exact repeats after one snippet was cached. Median call time was 2.57 ms for misses and 0.062 ms for hits, a 41.9× ratio on that local microbenchmark. It is not a concurrent or end-to-end service benchmark.”

### “Have you load-tested throughput?”

“No. These runs were sequential and the HTTP integration harness did not complete, so I do not have a defensible requests-per-second or concurrency claim yet.”

## 7. Model and claim caveats

The source/context audit notes that some newly added neural components do not have trained checkpoints in the repository: the code classifier uses a deterministic randomly initialized head; MalConv/MalImg loaders fall back to initialized architectures when weights are absent; and the vision tower describes itself as simulating MobileCLIP. Do not attribute measured classifier quality to those models without verifying the loaded weights and benchmark setup. The deterministic AST/secret checks, request wiring, caching behavior, and unit-tested pathways are separate claims.

## 8. What to measure next for a stronger Gravia fit

1. Resolve the ASGI/TestClient or lifespan-startup problem and run the HTTP route tests.
2. Reproduce the historical detection benchmark with the intended Stage 2 backend and device.
3. Run an endpoint-level benchmark with warm-up, fixed request mix, concurrency levels, throughput, median/P95/P99 latency, and error rate; isolate upstream LLM time from gateway inspection time.
4. Benchmark code, binary, image/document, and tool-call routes separately over documented payload sizes and cold/warm cache states.
5. Confirm model checkpoint provenance before reporting detection quality for the new scanners.
