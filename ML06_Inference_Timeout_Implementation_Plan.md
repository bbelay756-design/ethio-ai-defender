# ETHIO-AI Defender — ML-06 Implementation Plan: Inference Timeout, Process Isolation, and Artifact Identity

**Milestone:** ML-06  
**Document Version:** 2.0  
**Date:** October 28, 2026  
**Status:** IMPLEMENTATION READY  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  

---

## 1. Phase 1: Pre-Flight Audit & Artifact Identity Resolution

### 1.1 Git Status & Environment Coordinates
- **Branch:** `my-feature-branch`
- **Git Working Tree:** Clean (0 unstaged changes).
- **Recent Commits:**
  - `4a878ba`: `feat(ml): validate upstream reference parity and acquire isolated vendor reference (ML-08A)`
  - `82dae54`: `feat(ml): integrate ML shadow mode, feature parity validation, and audit reports`
- **Pre-Test Operational Database Checksum:**
  - File: `storage/defender.db`
  - Size: 31,707,136 bytes
  - Computed SHA-256: `67ef7e677c63bae242fa9e9f3e591fa1571295598a9bac59849a1a412db8d426`

### 1.2 Model Artifact Identity Resolution
The audit resolved the recorded digest discrepancy across model artifacts:

1. **Artifact in `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib`:**
   - Size: 1,609,815 bytes.
   - SHA-256: `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`.
   - Sidecar `model.joblib.sha256`: Matches `f2fd3ed4...`.
   - Metadata `metadata.json`: Name `ember-v2-baseline-hgb-subset80k`, 80,000-sample balanced stratified subset training, seed 42, fingerprint `b236bf53c97cb614597ae388cd2b52de68aa559408c54c4f6c05a3836f0819c6`.
   - **Audit Provenance:** This is the authoritative baseline model formally audited and approved in `ML04_Baseline_Training_Evaluation_Report.md` and `ML05_Model_Review_Report.md`.

2. **Artifact in `storage\models\ember_baseline_v1\model.joblib`:**
   - Size: 1,607,626 bytes.
   - SHA-256: `baf625e1787c6e3b6e2648caea2020435a95f077c53a1d5b52d1087efb25e59b`.
   - Sidecar `model.joblib.sha256`: Matches `baf625e1...`.
   - Metadata `metadata.json`: Name `ember-v2-baseline-hgb`, 208,291-sample training run from full partitions.
   - **Provenance:** Represents an auxiliary experiment on the full partition set.

3. **Conclusion & Decision:**
   Neither artifact is corrupted. `f2fd3ed4...` is the authoritative baseline model established by ML-04/ML-05. The hardcoded constant `TRUSTED_BASELINE_MODEL_SHA256 = "f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684"` in `app/ml/classifier.py` is verified, accurate, and remains unchanged.

---

## 2. Phase 2: Bounded Inference Architecture Design

### 2.1 The Hard Process Boundary
Native C/C++ execution (LIEF parsing) and OpenMP multithreading in `scikit-learn` do not poll Python's bytecode evaluation loop or GIL interrupts. Thread timeouts cannot terminate runaway native code. 
A separate OS process via `multiprocessing.get_context("spawn")` establishes a true hard isolation boundary. On timeout, the parent terminates the worker with Windows `TerminateProcess()` (`worker.terminate()`), ensuring immediate release of CPU, threads, and memory.

### 2.2 Worker Process Management
- **Single Persistent Worker:**
  - Cold startup of Python 3.14 on Windows importing `scikit-learn`, `numpy`, and `joblib` takes 6.0 to 7.5 seconds. Re-spawning per task would consume almost the entire 10-second default timeout on module imports alone.
  - A managed worker is pre-warmed / lazily initialized once and reused across tasks for sub-100ms inference.
- **Strict Wall-Clock Deadline:**
  - Enforced via `pipe.poll(timeout_seconds)`.
  - On timeout expiration:
    1. Parent immediately issues `worker.terminate()`.
    2. Parent waits up to 0.5s for exit; if still running, issues `worker.kill()`.
    3. Parent joins and closes pipe handles.
    4. Worker instance reference is reset to `None` to prevent reuse of a dead process.
    5. A fresh worker will be lazily spawned on the next inference request.
- **Worker Crash & Malformed Output Protection:**
  - Parent wraps IPC in robust `try...except (EOFError, BrokenPipeError, ConnectionResetError)`.
  - Parent rigorously validates worker response payload structure, ensuring numeric types, finite values, and valid probabilities in $[0.0, 1.0]$.
- **Bounded Resource Consumption:**
  - Maximum payload size strictly checked prior to IPC dispatch (`settings.MAX_FILE_SIZE_BYTES`).
  - Single worker concurrency lock ensures exactly 1 child process runs at any time.
  - Automatic recycling after 500 tasks prevents long-term memory accumulation.
- **Fail-Safe Non-Interference:**
  - ML failures, timeouts, and unverified states return structured `MLAnalysisResult` with `available=False` or `is_reliable=False`.
  - Deterministic pipeline analyzers (PE, Hashes, YARA, Strings) and threat scoring remain 100% unaffected.
