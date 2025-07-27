# ✅ Contributor Checklist

Before submitting a pull request, please verify the following:

- [ ] Your rule targets a specific variant or builder generation.
- [ ] You followed the rule template in /docs/rule_template.md.
- [ ] The `meta` section contains author, date, and description.
- [ ] You added at least one .json file from CAPA or DIE.
- [ ] The file paths follow this structure:
```
Variant_Name/
├── Builder.yara
├── CAPA/
│ └── <hash>.json
└── DIE/
└── <hash>.json
```
- [ ] Rule was tested on actual sample and avoids false positives.
- [ ] Your commit messages are clear and action-specific.

❗ Pull requests that lack metadata or violate folder structure will be rejected.

You can find guidance in the CONTRIBUTING.md and rule_template.md files.