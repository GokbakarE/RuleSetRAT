import "pe"
import "math"
rule C_One_v1_0_0
{
    meta:
        description = "Detects C_One_v1_0_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 EC 44 56 FF 15 8C 10 40 00 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D 46 EB 0A 3C 20 7E 06 46 80 3E 20 7F FA 8A 06 84 C0 74 04 3C 20 7E E9 83 65 E8 00 8D 45 BC 50 FF 15 90 10 40 00 E8 5D 00 00 00 68 AC 10 40 00 68 A8 10 40 00 E8 34 00 00 00 F6 45 E8 01 59 59 74 06 0F B7 45 EC EB 03 6A 0A 58 }
        $EP2 = { 87 25 08 62 40 00 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3A AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 24 AC D1 E8 74 2D 13 C9 EB 18 91 48 C1 E0 08 AC FF 53 04 3B 43 F8 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 9F 5E AD 97 }

        $s1 = "GetProcAddress" 
        $s2 = "LoadLibraryA" 
        $s3 = "KERNEL32.dll" nocase
        $s4 = "_^[Y" 
    condition:
        pe.is_pe and
        (pe.entry_point == 0x154 or pe.entry_point == 0x1E78) and
        ($EP at (pe.entry_point) or $EP2 at (pe.entry_point)) and
        (uint32(0x34) == 0x00000154 or uint32(0xE8) == 0x00002C78) and//Optional Header's EP 
        (uint32(0x3C) == 0x0000000C or uint32(0xF0) == 0x00001000) and//Optional Header's Base of Data
        (pe.timestamp == 0x21475346 or pe.timestamp == 0x42FA3577) and
        (pe.data_directories[1].virtual_address == 0x2D84 and pe.data_directories[1].size == 0x3C or pe.data_directories[1].virtual_address == 0x61C4 and pe.data_directories[1].size == 0x84) and
        pe.data_directories[2].virtual_address == 0x0 and pe.data_directories[2].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        (math.entropy(0, filesize) >= 5.89 and math.entropy(0, filesize) <= 5.99 or math.entropy(0, filesize) >= 7.55 and math.entropy(0, filesize) <= 7.65) and
        filesize >= 1 * 1024 and filesize <= 15 * 1024 and
        4 of ($s*)
}
