# 🤝 Contributing to RuleSetRAT

Welcome! 👋  
RuleSetRAT is an open-source malware analysis initiative focused on building highly accurate variant-specific YARA rules and analysis artifacts for legacy and modern Remote Access Trojans (RATs). We welcome community contributions that align with our technical and ethical standards.

---

## 📐 Contribution Guidelines

Before contributing, please ensure your changes align with the following:

- ✅ Each YARA rule should target a specific variant or builder (not generic families).
- ✅ Metadata must include author, date, description, and license fields.
- ✅ Supporting files (CAPA, DIE JSON) must reflect the same sample.
- ✅ All files should be placed in the correct folder structure:
```
RAT_Name/
├── Builder.yara
├── CAPA/
│ └── <hash>.json
├── DIE/
  └── <hash>.json
```
- We currently do not accept live malware binaries or encrypted samples via pull requests.

---

## 🔁 Commit History Philosophy

You may notice that the project has an unusually high number of commits. This is intentional.

We chose to maintain a highly granular commit structure in order to:

- Preserve clear traceability of every change
- Ensure the repository is auditable and reviewable at every step
- Isolate actions such as renaming, metadata updates, and file moves into distinct units
- Facilitate peer review and collaborative scalability

Rather than batch changes into large opaque commits, we deliberately logged each minor update as a standalone commit to enhance historical clarity. This discipline ensures that future contributors and researchers can trace every action taken in the project with precision.

---

## ⚙️ How to Submit

1. Fork this repository
2. Create a new branch: feature/my_new_rule
3. Add your YARA rule and supporting files
4. Commit with a clear message
5. Submit a pull request with a short description of your addition

---

## 🤖 Contributor Notes

We encourage contributions related to:

- New builder variants (especially rare or undocumented ones)
- Metadata correction
- CAPA or DIE improvements
- Documentation in /docs
- Rule optimization (less FP, better matching)

We may ask for hashes, PE headers, or entropy range to validate rule accuracy.

Thank you for helping expand this malware detection knowledgebase.  
Your contribution may help threat researchers worldwide.

—
GokbakarE
2025