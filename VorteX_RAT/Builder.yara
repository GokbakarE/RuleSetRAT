rule VorteX_RAT
{
    meta:
        description = "Detects VorteX_RAT malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "MIT License"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 56 B8 EC E6 43 00 E8 D2 82 FC FF BB 7C 1A 44 00 BE 44 1C 44 00 33 C0 55 68 DA EA 43 00 64 FF 30 64 89 20 B2 01 A1 88 83 43 00 E8 F2 54 FC FF 89 06 8B 06 C6 40 08 00 68 E8 EA 43 00 E8 DC 85 FC FF 68 D0 07 00 00 E8 7E EC FC FF B8 40 1C 44 00 E8 78 D2 FF FF 84 C0 0F 84 C5 01 00 00 BA AC 1A 44 00 B9 64 00 00 00 A1 40 }
        $s1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" 
        $s2 = ";.;2;6;:;>;B;F;J;N;R;V;Z;^;b;f;??I?P?W?b?w?~?"
        $s3 = "4(4044484<4@4D4H4L4P4T4X4\\4`4d4h4l4p4t4x4|4"
        $s4 = "6!6%6)6-6165696=6A6E6I6M6Q6U6Y6]6a6e6i6=8"
        $s5 = "9$9(90949@9D9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s6 = "6(6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6|6" 
        $s7 = "2:3>3B3F3J3N3R3V3Z3^3b3f3j3n3r3v3z3~3" 
        $s8 = "$TMultiReadExclusiveWriteSynchronizer"
        $s9 = "2$242<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2" 
        $s10 = "1$1(1,1014181<1@1D1H1L1P1Z1^1p1"
    condition:
        pe.is_pe and
        pe.entry_point == 0x3DC34 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0003E834 and//Optional Header's EP 
        uint32(0x130) == 0x0003F000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x42000 and pe.data_directories[1].size == 0x198A and
        pe.data_directories[2].virtual_address == 0x4A000 and pe.data_directories[2].size >= 0x1A80 and pe.data_directories[2].size <= 0x1AFF and
        pe.data_directories[5].virtual_address == 0x46000 and pe.data_directories[5].size == 0x338C and
        pe.data_directories[9].virtual_address == 0x45000 and pe.data_directories[9].size == 0x18 and
        pe.imports("URLMON.DLL") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.53 and math.entropy(0, filesize) <= 6.63 and
        filesize >= 275 * 1024 and filesize <= 285 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
