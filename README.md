# 🛡️ RuleSetRAT: Variant-Specific YARA Rules & Malware Builder Analysis

This repository provides a curated set of variant-specific YARA detection rules and detailed static analysis reports for various Remote Access Trojan (RAT) families and builder samples. The goal is to support professionals in the cybersecurity field with actionable intelligence, reverse engineering insights, and precision detection capabilities.

> ⚠️ This project is strictly intended for educational, academic, and ethical cybersecurity research purposes.

---

## 📦 Repository Structure

Each malware family or builder variant is organized into its own dedicated folder, containing:

- `Builder.yara` – Custom YARA rule tailored to the variant’s unique byte patterns and PE characteristics
- `CAPA/` – Generated static analysis output from FireEye’s CAPA tool (JSON format)
- `DIE/` – PE metadata and obfuscation insights from Detect It Easy (DIE) (JSON format)

All detection rules are manually reviewed and tested to ensure variant-level granularity, enabling high-confidence threat identification.

---

## 🧪 Methodology & Goals

This project is the product of extensive malware reverse engineering work. Each sample has been statically analyzed using multiple tools and methodologies, with the goal of:

- Crafting fine-tuned YARA rules capable of identifying specific variants or builder generations
- Documenting functional capabilities via CAPA
- Extracting PE structure and obfuscation metadata via DIE

By combining rule-based detection with structured static analysis data, this repository aims to provide a comprehensive knowledge base for malware researchers and defenders.

---

## 🧬 Sample Provenance & Integrity

All static analysis and detection rules in this project are based on binary samples manually generated in controlled QEMU sandbox environments. These samples were produced by executing legacy malware builder applications and capturing their compiled payloads under isolated conditions.

Notably, many of these samples are not available on public platforms such as VirusTotal or Hybrid Analysis — they were created from builder stubs using internal, private infrastructure.

⚠️ For ethical and legal reasons, we do not publicly share any decrypted or functional malware samples.

We also do not provide full behavioral analysis traces to the public at this time. Select metadata (e.g., YARA hits, CAPA features, PE headers) is available within the repository for research purposes.

Requests for sample access, behavioral logs, or sandbox exports will be respectfully declined.

---

## 🔁 Commit Structure & Workflow

We deliberately maintained a granular commit history. Each change, rule addition, or metadata update was committed separately to preserve traceability and make the repository auditable.

> This disciplined commit structure enhances transparency, facilitates peer review, and ensures that future updates can be efficiently tracked and validated.

---

## ⚠️ Legal & Ethical Disclaimer

All materials in this repository are provided strictly for:

- Academic research
- Threat intelligence development
- Defensive cybersecurity applications
- Reverse engineering education

The use of any part of this repository for malicious, unethical, or illegal activities is strictly prohibited.

We do not host any live or executable malware samples. All included samples (if present) are encrypted, non-functional, and intended only for controlled analysis in secure environments.

The maintainers assume no responsibility for misuse of this content. Users are expected to adhere to all relevant laws, regulations, and institutional policies.

---

## 📜 License

Please refer to the LICENSE file for terms of use, redistribution, and contribution guidelines.

---

© 2025 GokbakarE. All rights reserved.
