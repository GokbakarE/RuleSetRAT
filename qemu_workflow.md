# 🖥️ QEMU Workflow – Sample Generation Process

This document describes how malware samples were generated in a secure, reproducible way using QEMU virtualization.

## ⚙️ Setup

- Guest OS: Windows XP SP3
- Host OS: Linux (Ubuntu 22.04)
- Virtualization: QEMU + qcow2 snapshotting
- Network: Disabled (airgapped)
- Snapshot rollback enabled before and after each builder execution

## 🔄 Workflow

1. Prepare a clean qcow2 image with the target OS.
2. Install builder in the guest.
3. Execute builder to generate payload.
4. Export resulting PE sample to host using shared folder or QEMU copy-paste.
5. Immediately revert guest to clean snapshot using `qemu-img snapshot -a clean`.

No builder was executed more than once per snapshot session.  
This ensures clean, reproducible builds and prevents contamination.

⚠️ No live malware remains in storage. Only analysis metadata is retained.

## 🛡️ Ethics & Safety

- No network connectivity
- No persistent disk writes
- Builders handled in a non-interactive, isolated VM

Samples generated this way form the basis of every YARA rule in the repository.