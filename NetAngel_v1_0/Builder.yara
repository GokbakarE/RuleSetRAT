rule NetAngel_v1_0
{
    meta:
        description = "Detects NetAngel_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 B8 3C 91 46 00 E8 B3 D0 F9 FF 8B 1D D0 B7 46 00 8B 03 E8 92 9A FE FF 8B 03 33 D2 E8 99 96 FE FF 8B 03 C6 40 5B 00 8B 0D 1C B9 46 00 8B 03 8B 15 D0 25 46 00 E8 88 9A FE FF 8B 0D 64 B9 46 00 8B 03 8B 15 F0 22 46 00 E8 75 9A FE FF 8B 03 E8 EE 9A FE FF 5B E8 BC B0 F9 FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "9$9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s3 = "2$2,2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s4 = "9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9"
        $s5 = "IsThemeBackgroundPartiallyTransparent"
        $s6 = "!TIdMappedPortOutboundConnectEvent"
        $s7 = "!EIdSocksServerNetUnreachableError"
        $s8 = "<<<D<H<L<P<T<X<\\<`<d<h<l<p<t<x<|<"
        $s9 = "WSAGetServiceClassNameByClassIdW"
        $s10 = "<$<(<,<0<4<8<<<@<D<H<L<P<\\<f<j<{<"
    condition:
        pe.is_pe and
        pe.entry_point == 0x6882C and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0006942C and//Optional Header's EP 
        uint32(0x130) == 0x0006A000 and // Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[5].virtual_address == 0x73000 and pe.data_directories[5].size == 0x807C and
        pe.data_directories[9].virtual_address == 0x72000 and pe.data_directories[9].size == 0x18 and
        pe.data_directories[1].virtual_address == 0x6E000 and pe.data_directories[1].size == 0x255C and
        pe.data_directories[2].virtual_address == 0x7C000 and pe.data_directories[2].size == 0xB600 and
        pe.imports("winmm.dll") and
        pe.imports("SHELL32.DLL", "SHEmptyRecycleBinA") and
        math.entropy(0, filesize) >= 6.55 and math.entropy(0, filesize) <= 6.65 and
        filesize >= 510 * 1024 and filesize <= 520 * 1024 and
        8 of ($s*)
}
