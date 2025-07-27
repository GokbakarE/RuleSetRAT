# 🧾 YARA Rule Template

Below is the standardized YARA rule template used throughout the RuleSetRAT repository. All rules must adhere to this structure.

```yara
import "pe"
import "math"

rule [Variant_Name]
{
    meta:
        description = "Detects [Variant_Name] malware variant"
        author = "GokbakarE"
        date = "YYYY-MM-DD"
        license = "GNU AGPLv3"

    strings:
        $s1 = "string_1"
        $s2 = { byte_sequence }
        $s3 = "optional_string_3"
        ...
    
    condition:
        pe.is_pe and
        math.entropy(0, filesize) >= X and
        filesize <= Y and
        [additional PE header checks] and
        [import filters] and
        [string conditions]
}
```
## 🧠 Guidelines:

- Include minimum 5-8 distinguishing strings or byte sequences.
- Always validate entry point, entropy, and PE header fields if applicable.
- Use comments where needed.
- Prioritize false-positive reduction.
- 📌 Rules must detect a specific version of a builder or compiled output, not general malware families.