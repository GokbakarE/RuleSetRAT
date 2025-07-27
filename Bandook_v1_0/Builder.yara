import "pe"
import "math"
rule Bandook_v1_0
{
    meta:
        description = "Detects Bandook_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 87 25 EC 46 40 00 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3A AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 24 AC D1 E8 74 2D 13 C9 EB 18 91 48 C1 E0 08 AC FF 53 04 3B 43 F8 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 9F 5E AD 97 }
        $s5 = "FSG!"
        $s1 = "GetProcAddress"
        $s2 = "s$iHM"
        $s3 = "cons1|"
        $s4 = "KERNEL32.dll" nocase
        $s6 = "LoadLibraryA"
    condition:
        pe.is_pe and
        pe.entry_point == 0x154 and
        $EP at (pe.entry_point) and
        uint32(0x34) == 0x00000154 and//Optional Header's EP 
        uint32(0x3C) == 0x0000000C and//Optional Header's Base of Data
        pe.timestamp == 0x21475346 and
        pe.data_directories[1].virtual_address == 0x46A8 and pe.data_directories[1].size == 0x84 and
        pe.data_directories[2].virtual_address == 0x0 and pe.data_directories[2].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[9].virtual_address == 0x0 and pe.data_directories[9].size == 0x0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        math.entropy(0, filesize) >= 7.0 and math.entropy(0, filesize) <= 7.1 and
        filesize >= 0 * 1024 and filesize <= 10 * 1024 and
        pe.overlay.size == 0 and
        5 of ($s*)
}
