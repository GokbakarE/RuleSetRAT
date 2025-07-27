# 📁 Repository Structure

This project is organized to facilitate clarity, extensibility, and precise variant-level documentation.

Each malware builder variant resides in its own folder:

```
Variant_Name/
├── Builder.yara ← Variant-specific YARA rule
├── CAPA/
│ └── <hash>.json ← CAPA static analysis output
└── DIE/
└── <hash>.json ← DIE metadata and PE header info
```

🧠 Notes:

- Folder names correspond to known builder versions or family identifiers (e.g., Dark_Connect_v3_4).
- File names match sample SHA256 hashes (excluding extension).
- No executable binaries are included. All content is static or metadata.

⚠️ Do not place unrelated or generic rules in these folders. This repository is focused on variant-specific detection only.
