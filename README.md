# ETHIO-AI Defender (የኢትዮ-ኤአይ መከላከያ)
**AI-Powered Defensive Malware Analysis and Reverse Engineering Platform for Ethiopia**

---

## 🛡️ Project Overview
**ETHIO-AI Defender** is an educational and defensive cybersecurity platform dedicated to the static analysis and reverse-engineering triage of Windows Portable Executable (PE) binaries (`.exe`, `.dll`) without execution.

### 📐 Core Workflow Principle
```
OBSERVED DATA
      ↓
STATIC ANALYSIS
      ↓
SECURITY INDICATORS
      ↓
CORRELATION
      ↓
HEURISTIC RISK SCORE
      ↓
AI INTERPRETATION
      ↓
HUMAN-READABLE REPORT (English / Amharic)
```

---

## 🔒 Security Assurance & Safety
* **Zero Execution Guarantee**: Files uploaded to this platform are never executed or invoked in any shell.
* **Strict Static Inspection**: Magic byte header validation, section analysis, entropy, import inspection.
* **Path Traversal & Injection Prevention**: Client filenames are completely sanitized, and files are quarantined in isolated directories with randomized identifiers.
* **AI Fact-Grounding**: The AI model analyzes strictly structured static indicators and never hallucinates evidence or target attribution without concrete indicators.

---

## 📦 Implemented Modules

### ✅ Module 01: Secure File Intake
- Enforces strict file size thresholds (default: 50MB) to mitigate DoS.
- Strips directory traversal paths, control characters, and Windows reserved names.
- Validates DOS `MZ` (`0x4D 0x5A`) and PE header signatures.
- Computes SHA-256, SHA-1, and MD5 hashes safely.
- Stores samples in isolated quarantine storage with secure randomized names.

---

## 🚀 Running the Project & Tests

### 1. Run Unit Tests:
```powershell
python -m unittest discover tests
```

### 2. Run Module 01 Demo:
```powershell
python -m app.analyzers.file_intake
```
