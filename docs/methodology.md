# 🧪 Methodology – Rule Generation Pipeline

This document explains the technical process used to produce each YARA rule and corresponding analysis reports.

## 🔬 1. Sample Generation

- Builders executed in QEMU sandbox
- PE payloads extracted after compilation
- Each sample uniquely identified by SHA256

## 🛠️ 2. Static Analysis

Tools used:
- CAPA (https://github.com/mandiant/capa)
- Detect It Easy (https://github.com/horsicq/Detect-It-Easy)
- Custom entropy calculator (Python)
- Manual disassembly (if required)

Outputs:
- CAPA: json structure of detected capabilities
- DIE: PE header, compiler metadata, section entropy

## 📜 3. Rule Design

YARA rules built around:
- Unique byte patterns (e.g., $EP)
- PE header characteristics (entry point, timestamps, base of data)
- Import table filters (e.g., mpr.dll, rasapi32.dll)
- High-entropy regions
- Minimum 7–10 unique strings per rule
- Strict size bounds (±5 KB)

## ✅ 4. Rule Validation

- Each rule tested against at least 1 original sample
- Rule must not trigger on unrelated RATs or benign binaries
- False positives reviewed via custom dataset

This layered process ensures each rule is precise, resilient, and reproducible.
