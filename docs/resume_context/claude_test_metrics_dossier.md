# Sentinel Test and Metrics Dossier

**Prepared:** 2026-11-04  
**Purpose:** Give Claude the verified project, test, benchmark, and performance context needed to help revise the Sentinel CV bullets for Gravia's backend intern role.

## Instructions for interpreting this dossier

- Treat code and observed command output as primary evidence.
- Keep the previously recorded 662-sample result as a real historical benchmark. A new CPU/fallback run is a separate configuration and does not invalidate or replace it.
- Clearly distinguish full-system measurements from isolated component microbenchmarks.
- Do not claim end-to-end HTTP latency, throughput, production load, or high concurrency: those were not measured successfully in this task.
- The fresh full-judge benchmark used a CPU-only runtime and Stage 2 fallback because `llama-cpp-python` was not installed. Do not compare it directly to the stored benchmark as though the setup were identical.

## Project and test scope

Sentinel is a FastAPI security gateway in front of LLM traffic. The code includes an ingress detector, output-side DLP and SSE interruption, canary tokens, RAG scanning, threat-rule synthesis, and newer scanners for code, binaries, images/documents, and agent tool calls, plus an isolated red-team campaign runner. Relevant entry points include:

- `sentinel/core/gateway/app.py`
- `sentinel/core/detection/judge.py`
- `sentinel/core/gateway/stream_interceptor.py`
- `sentinel/core/codesec/engine.py`
- `sentinel/core/malware/engine.py`
- `sentinel/core/vision/engine.py`
- `sentinel/core/detection/tool_guardrail.py`
- `sentinel/core/redteam/runner.py`

The repository's context inventory records 171 tests in nine test files. That is a prior collection inventory; a completed fresh full-suite run was not obtained in this task.

## Existing recorded prompt-injection benchmark

Source: `sentinel/tests/samples/benchmark_report_deepset_all_662.json`. The existing CV's 96.4% precision and 1.0% false-positive rate come from this stored report and are real historical results.

| Metric | Recorded value |
|---|---:|
| Dataset | `deepset/prompt-injections` |
| Samples | 662 total: 263 attacks, 399 benign |
| TP / FP / TN / FN | 107 / 4 / 395 / 156 |
| Precision | 96.40% |
| Recall | 40.68% |
| False-positive rate | 1.00% |
| Accuracy | 75.83% |
| F1 | 0.5722 |
| Average judge latency | 678.02 ms per prompt |
| Total recorded run time | 448.87 s |

The evaluator in `sentinel/tests/benchmark_full_662.py` marks a prompt as detected when the judge returns either `BLOCK` or `FLAG`. It builds the 662-row dataset from both the public dataset's train and test splits. The latency is per-prompt **judge evaluation**, not full HTTP gateway latency, upstream LLM time, or a production load-test result. The reported recall means 156 of 263 attacks were missed; include that context in interview discussion. The report was not overwritten during the fresh run below.

## Fresh full-judge benchmark from this task

This was a new in-memory run over the same 662-row local dataset, using the same classification rule (`BLOCK` or `FLAG` = detected). It did not write a new report file.

**Runtime:** temporary Python 3.12.3 environment under `/tmp`; CPU-only PyTorch 2.14.0; `OMP_NUM_THREADS=1`, `MKL_NUM_THREADS=1`, and `OPENBLAS_NUM_THREADS=1`; local DeBERTa weights at `models/sentinel_deberta`. The configured local GGUF arbiter was selected, but `llama-cpp-python` was unavailable. Stage 2 therefore returned its local fallback result. No cloud arbiter call was used.

| Metric | Fresh CPU/fallback run |
|---|---:|
| Samples | 662 |
| TP / FP / TN / FN | 104 / 20 / 379 / 159 |
| Precision | 83.87% |
| Recall | 39.54% |
| False-positive rate | 5.01% |
| Accuracy | 72.96% |
| F1 | 0.5375 |
| Mean judge latency | 841.07 ms |
| Median judge latency | 720.76 ms |
| P95 judge latency | 1,566.66 ms |
| Maximum judge latency | 3,801.07 ms |
| Total elapsed time | 556.80 s |

These results are useful as a measured CPU/fallback configuration, but are not an apples-to-apples replacement for the stored result: the Stage 2 local model was unavailable at runtime and the device/runtime differs. Do not present the fresh run as a regression or improvement without first matching the original model, backend, device, and dependency setup.

## PatternHunter-only corpus diagnostic

An additional one-off run applied `PatternHunter.scan()` to each of the 662 prompts. This isolates the regex/signature layer; it is **not** the full judge. Thresholds below were exploratory decision cutoffs on the returned score, not the production judge's full decision rule.

| Standalone score cutoff | TP / FP / TN / FN | Precision | Recall | FPR | Accuracy | F1 |
|---|---:|---:|---:|---:|---:|---:|
| `score >= 40` | 16 / 18 / 381 / 247 | 47.06% | 6.08% | 4.51% | 59.97% | 0.1077 |
| `score >= 80` | 5 / 0 / 399 / 258 | 100.00% | 1.90% | 0.00% | 61.03% | 0.0373 |

Measured `PatternHunter.scan()` wall time over the corpus: mean 0.4851 ms, median 0.3163 ms, P95 1.3355 ms, maximum 13.4219 ms. These numbers demonstrate the behavior of the isolated first-pass detector, not ensemble quality; they are not recommended as CV claims.

## Cache performance microbenchmark

The measured path was `CodeSecurityEngine.scan_code()` in `sentinel/core/codesec/engine.py`. The engine uses a bounded 1,024-entry SHA-256-keyed cache (`MAX_CACHE_SIZE` in `sentinel/core/codesec/config.py`). The microbenchmark scanned 60 unique, short Python snippets, then repeated one exact snippet 2,000 times and asserted the returned result had `cached == True`.

| Workload | Sample count | Median | P95 |
|---|---:|---:|---:|
| Unique/uncached short snippets | 60 | 2.5728 ms | 5.2928 ms |
| Exact repeated warm-cache hit | 2,000 | 0.0615 ms | 0.1243 ms |

The ratio of the two medians is 41.9×. This is a local, single-process microbenchmark for small code snippets. It does not measure HTTP, database logging, concurrent callers, cold process startup, large files, or a production workload. The cache flag assertion passed.

## Canary matching microbenchmark

The measured method was `CanaryEngine.check_leak()` in `sentinel/core/security_vectors/canary.py`. The test generated a real token, checked a matching string of about 260 characters and a nonmatching string of 248 characters, and asserted both outcomes. `timeit.repeat` ran nine batches of 100,000 calls per case.

| Case | Calls | Median time per check | Batch min–max |
|---|---:|---:|---:|
| Token present | 900,000 | 0.000353 ms (0.353 µs) | 0.000296–0.000547 ms |
| Token absent | 900,000 | 0.000285 ms (0.285 µs) | 0.000255–0.000341 ms |

The pass assertions confirmed match detection and clean-text rejection. This measures only Python's in-memory exact substring check. It is not total stream interception latency, an HTTP latency, or a per-token production service benchmark.

## Automated tests and verification

The machine did not initially have an importable `pytest` installation. A temporary environment was created under `/tmp/sentinel-test-venv` with CPU PyTorch and the dependency versions recorded in the repository context. `python-multipart` was added to that temporary environment because FastAPI requires it to register file-upload routes; no project dependency file was changed.

1. `python3 -m compileall -q core dashboard tests scripts` — passed (syntax compilation only).
2. `env OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 /tmp/sentinel-test-venv/bin/python -m pytest -q tests/test_code_security.py -k 'not gateway_api'` — **27 passed, 3 deselected**, 17.22 s.
3. `env OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 /tmp/sentinel-test-venv/bin/python -m pytest -q -o faulthandler_timeout=60 tests/test_components.py tests/test_detection.py tests/test_malware_scanner.py tests/test_redteam.py tests/test_security_vectors.py tests/test_tool_guardrail.py tests/test_vision.py -k 'not api_scan_file and not FastAPIRedTeamEndpoints and not api_scan_image and not api_scan_document and not multimodal_chat_completion_hook and not gateway_inspect_tool'` — **114 passed, 16 deselected**, 146.33 s; three dependency/deprecation warnings.

Combined: **141 selected tests passed; 19 endpoint-related tests deselected** across those commands. The 11 tests in `tests/test_gateway.py` were not run.

### Endpoint-test limitation

After adding `python-multipart`, collection succeeded, but the full `pytest -q` run stopped progressing at `test_gateway_api_scan_code_clean`. A focused 15-second faulthandler capture showed the test thread waiting inside Starlette `TestClient`/HTTPX while the portal event-loop thread was idle in selector wait. Pinning Starlette to the version listed in the project context did not resolve it. The endpoint was not demonstrated to be broken; the request did not complete in this harness.

A separate Uvicorn smoke attempt used a temporary working directory/database and the local model, but application lifespan startup did not finish its DeBERTa warm-up after more than two minutes. The server never accepted `/health`; the process was stopped. This yielded no API latency data and did not modify the project's `gateway.db`.

Final `git status --short` and `git diff --stat` were empty. The tracked historical benchmark report remains unchanged.

## Resume use and follow-up

- Keep the recorded 662-sample result as a historical benchmark and disclose its 40.68% recall when discussing methodology.
- The strongest new Gravia-relevant number from this task is the **41.9× repeat-scan cache microbenchmark**, with its small-input and local-only scope stated.
- The canary helper's sub-microsecond check is technically measured but too narrow to describe as end-to-end or production latency.
- Do not claim API throughput, p95 request latency, concurrency capacity, or a fresh end-to-end performance win from these runs.
- For comparable ensemble metrics, rerun on the intended device with the same DeBERTa and functioning Stage 2 backend as the stored run. For service latency, first make the gateway lifespan and HTTP test harness complete reliably, then measure the real endpoint path under a documented load profile.
