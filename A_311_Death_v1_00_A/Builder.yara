rule A_311_Death_v1_00_A
{
    meta:
        description = "Detects A_311_Death_v1_00_A malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 }
        $s1 = "56789+/_7U"
        $s2 = "<t>u6v.w`&O"
        $s3 = "GetProcAddress"
        $s4 = "LoadLibraryA"
        $s5 = "KERNEL32.dll"
        $s6 = "x8pVr:Pv"
        $s7 = "OFTWA6RE"
        $s8 = "KLMNpQRS"
        $s9 = "aT!nNPmw"
        $s10 = "=>+Y=#n"
    condition:
        pe.is_pe and
        pe.entry_point == 0x57B3 and
        $EP at (pe.entry_point) and
        uint32(0x34) == 0x000125B3 and//Optional Header's EP 
        pe.timestamp == 0x21584450 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.data_directories[1].virtual_address == 0x12678 and pe.data_directories[1].size == 0x34 and
        pe.data_directories[2].virtual_address == 0xD000 and pe.data_directories[2].size == 0x3A0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        math.entropy(0, filesize) >= 7.6 and math.entropy(0, filesize) <= 7.7 and
        filesize >= 21 * 1024 and filesize <= 24 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
