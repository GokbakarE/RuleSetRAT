rule SilentSpy_2_1_0
{
    meta:
        description = "Detects SilentSpy_2_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 A0 90 47 00 E8 6C D8 F8 FF 68 F0 92 47 00 6A 00 6A 00 E8 DA D9 F8 FF E8 CD DA F8 FF 3D B7 00 00 00 75 0E A1 D8 B8 47 00 8B 00 E8 6A 03 FE FF EB 30 A1 D8 B8 47 00 8B 00 E8 D8 01 FE FF 8B 0D 08 B8 47 00 A1 D8 B8 47 00 8B 00 8B 15 70 60 47 00 E8 D8 01 FE FF A1 D8 B8 47 00 8B 00 E8 4C 02 FE FF E8 AF B2 F8 FF 00 00 00 }
        $s1 = "3$3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" 
        $s2 = "1$1(1,1014181<1@1D1H1L1P1T1X1\\1`1d1h1l1p1t1x1|1"
        $s3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s4 = "8-9195999=9A9E9I9M9Q9U9Y9]9a9e9i9m9q9u9y9}9"
        $s5 = "2(2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s6 = "6$60646<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" 
        $s7 = "ImmSetCompositionWindow" 
        $s8 = "$TMultiReadExclusiveWriteSynchronizer"
        $s9 = "http://www.microsoft.com/" 
        $s10 = "InitializeCriticalSection" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x78680 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00079280 and//Optional Header's EP 
        uint32(0x130) == 0x0007A000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x7D000 and pe.data_directories[1].size == 0x28CA and
        pe.data_directories[2].virtual_address == 0x8A000 and pe.data_directories[2].size == 0x4600 and 
        pe.data_directories[5].virtual_address == 0x82000 and pe.data_directories[5].size == 0x7388 and
        pe.data_directories[9].virtual_address == 0x81000 and pe.data_directories[9].size == 0x18 and
        pe.imports("winmm.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 6.56 and math.entropy(0, filesize) <= 6.66 and
        filesize >= 541 * 1024 and filesize <= 551 * 1024 and
        7 of ($s*)
}
