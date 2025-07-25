rule Slh_4_0
{
    meta:
        description = "Detects Slh_4_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 3E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 94 52 15 13 E8 1B D5 FE FF BB 84 7D 15 13 33 C0 55 68 EC 5C 15 13 64 FF 30 64 89 20 68 07 80 00 00 E8 16 D8 FE FF B8 04 5D 15 13 E8 BC 7E FF FF 8D 45 EC E8 BC 51 FF FF 8B 55 EC B8 34 7E 15 13 E8 EB CB FE FF 83 3D 34 7E 15 13 00 75 0F B8 34 7E 15 13 BA 20 5D 15 13 E8 D3 CB FE }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\"
        $s3 = "E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E"
        $s4 = "p|kkp]warAjv{Khm`oNnelnogNkzv2r"
        $s5 = "60686<6@6D6H6L6P6T6X6\\6`6d6r6z6"
        $s6 = "4(4044484<4@4D4H4L4P4T4X4\\4`4d4" 
        $s7 = "jmkrka{bdhjdq-ai)nq,l`ee8?<603" 
        $s8 = "http://www.assoftware.cjb.net"
        $s9 = "0,080<0@0D0H0L0P0T0b0j0r0z0" 
        $s10 = "7$7,7074787<7@7D7H7L7P7T7X7l7"
    condition:
        pe.is_pe and
        pe.entry_point == 0x1476C and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0001536C and//Optional Header's EP 
        uint32(0x130) == 0x00016000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x18000 and pe.data_directories[1].size == 0x142C and
        pe.data_directories[2].virtual_address == 0x1F000 and pe.data_directories[2].size >= 0x80 and pe.data_directories[2].size <= 0xFF and
        pe.data_directories[5].virtual_address == 0x1D000 and pe.data_directories[5].size == 0x1600 and
        pe.data_directories[9].virtual_address == 0x1C000 and pe.data_directories[9].size == 0x18 and
        pe.imports("IMAGEHLP.DLL") and
        pe.imports("advpack.dll", "IsNTAdmin") and
        math.entropy(0, filesize) >= 6.48 and math.entropy(0, filesize) <= 6.58 and
        filesize >= 95 * 1024 and filesize <= 105 * 1024 and
        pe.overlay.size == 0 and
        7 of ($s*)
}