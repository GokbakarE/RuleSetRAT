rule DDoSeR_3_4
{
    meta:
        description = "Detects DDoSeR_3_4 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "26-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 EC 53 33 C0 89 45 EC B8 A0 A2 41 00 E8 4E BF FE FF 33 C0 55 68 76 A4 41 00 64 FF 30 64 89 20 B2 01 A1 FC 6F 41 00 E8 F0 95 FE FF 8B D8 8B C3 E8 97 CE FF FF B8 78 C9 41 00 BA 8C A4 41 00 E8 44 A1 FE FF A1 78 C9 41 00 E8 8A F7 FF FF 68 B8 0B 00 00 E8 74 1D FF FF 68 98 A4 41 00 6A 00 6A 00 E8 1E C0 FE FF E8 F1 C0 FE FF 3D }
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "6(6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6"
        $s3 = "3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
        $s4 = "icon=%SystemRoot%\\system32\\SHELL32.dll,4"
        $s5 = "6,64686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6|6"
        $s6 = "$TMultiReadExclusiveWriteSynchronizer"
        $s7 = "1!1%1)1-1115191=1A1S1k1i3m3q3u3y3}3"
        $s8 = "8$8(80848<8@8H8L8T8X8`8d8l8p8x8|8" 
        $s9 = "sqlite3_bind_parameter_index" 
        $s10 = "\\Mozilla\\Firefox\\profiles.ini" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x19788 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0001A388 and //Optional Header's EP 
        uint32(0x130) == 0x0001B000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x1D000 and pe.data_directories[1].size == 0xF1E and
        pe.data_directories[2].virtual_address == 0x22000 and pe.data_directories[2].size >= 0x1400 and pe.data_directories[2].size <= 0x1600 and 
        pe.data_directories[5].virtual_address == 0x20000 and pe.data_directories[5].size == 0x1F38 and
        pe.data_directories[9].virtual_address == 0x1F000 and pe.data_directories[9].size == 0x18 and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "SHGetSpecialFolderPathA") and
        math.entropy(0, filesize) >= 6.44 and math.entropy(0, filesize) <= 6.54 and
        filesize >= 120 * 1024 and filesize <= 125 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}
