import "pe"
import "math"
rule Bandook_v1_2
{
    meta:
        description = "Detects Bandook_v1_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 87 25 ?? 72 14 13 61 94 55 A4 B6 80 FF 13 73 F9 }
        $s5 = "FSG!"
        $s1 = "GetProcAddress"
        $s2 = "i$_HU"
        $s3 = "mycon"
        $s4 = "KERNEL32.dll" nocase
        $s6 = "LoadLibraryA"
    condition:
        pe.is_pe and
        pe.entry_point == 0x154 and
        $EP at (pe.entry_point) and
        uint32(0x34) == 0x00000154 and//Optional Header's EP 
        uint32(0x3C) == 0x0000000C and//Optional Header's Base of Data
        pe.timestamp == 0x21475346 and
        pe.data_directories[1].virtual_address >= 0x7200 and pe.data_directories[1].virtual_address <= 0x72FF and pe.data_directories[1].size == 0x84 and
        pe.data_directories[2].virtual_address == 0x0 and pe.data_directories[2].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[9].virtual_address == 0x0 and pe.data_directories[9].size == 0x0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        math.entropy(0, filesize) >= 7.58 and math.entropy(0, filesize) <= 7.68 and
        filesize >= 0 * 1024 and filesize <= 10 * 1024 and
        pe.overlay.size == 0 and
        5 of ($s*)
}
