# Sample Analysis – Z_dem0n10

## 🧩 Overview

Z_dem0n10 is a lesser-known RAT builder variant dating back to early 2010s. It was acquired via a manually executed builder stub in a QEMU sandbox environment.

The compiled sample produced a PE file with high entropy, unique timestamp, and a consistent layout across multiple test builds.

## ⚙️ Rule Characteristics

- Entry Point: 0xA52E0
- Entropy: 6.58 - 6.68 (Highly packed or obfuscated)
- PE Timestamp: 0x2A425E19 (Rare, used for identification)
- Size Range: 752 KB to 762 KB
- Import DLLs: rasapi32.dll, mpr.dll (Specifically uses WNetEnumCachedPasswords)

## 🧪 Detection Strategy

1. Entry Point bytecode signature:
   - Matches unique prologue
   - Verified at runtime offset

2. PE structural fields:
   - Optional Header's EP and Base of Data were consistent across multiple builds
   - Data directories [1], [2], [5], [9] matched exactly in all generations

3. Strings of interest:
   - `"-----------PASSWORDS----------------------"` – Hardcoded dump section marker
   - `"System\\CurrentControlSet\\Control\\Print\\Printers"` – Targeted for enumeration
   - `"from=Z-dem0n&fromemail=Z-dem0n@xxx.net&subject="` – Unique email exfil header

4. Anti-fingerprint measure:
   - At least 9 of 10 strings must be present to reduce false positives

## 🚧 Builder Behavior (Internal)

- Each sample was generated using a clean snapshot
- Builder executed inside QEMU WinXP
- No network traffic allowed during compilation
- QCOW2 images reset after each generation

⚠️ Samples are not available for distribution. Metadata only.
