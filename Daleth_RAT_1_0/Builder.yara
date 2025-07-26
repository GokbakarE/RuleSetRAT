rule Daleth_RAT_1_0
{
    meta:
        description = "Detects Daleth_RAT_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 56 B8 50 3D 18 13 E8 22 2B FC FF BB C8 BB 18 13 BE 90 BD 18 13 33 C0 55 68 30 49 18 13 64 FF 30 64 89 20 B2 01 A1 B0 9F 17 13 E8 66 FC FB FF 89 06 68 40 49 18 13 E8 D2 2D FC FF 68 70 49 18 13 E8 C8 2D FC FF 68 98 49 18 13 E8 BE 2D FC FF 68 D0 07 00 00 E8 AC A2 FC FF B8 8C BD 18 13 E8 C2 B7 FF FF 84 C0 0F 84 F4 01 }
        $s1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        $s2 = "060:0>0B0F0J0N0R0V0Z0^0b0f0j0n0r0v0z0~0"
        $s3 = "$TMultiReadExclusiveWriteSynchronizer"
        $s4 = "E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E"
        $s5 = "1$1(10141<1@1H1L1T1X1`1d1l1p1x1|1"
        $s6 = "?$?,?0?4?8?<?@?D?H?L?X?x?"
        $s7 = "=$=,=4=<=D=L=T=\\=d=l=t=|="
        $s8 = "<$<,<4<<<D<L<T<\\<d<l<t<|<"
        $s9 = "UnhandledExceptionFilter"
        $s10 = "GetWindowThreadProcessId"
    condition:
        pe.is_pe and
        pe.entry_point == 0x43A48 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00044648 and //Optional Header's EP 
        uint32(0x130) == 0x00045000 and//Optional Header's Base of Data
        pe.timestamp == 0x4BCC379E and
        pe.data_directories[1].virtual_address == 0x4C000 and pe.data_directories[1].size == 0x214E and 
        pe.data_directories[2].virtual_address == 0x55000 and pe.data_directories[2].size >= 0x1B00 and pe.data_directories[2].size <= 0x1B30 and
        pe.data_directories[5].virtual_address == 0x51000 and pe.data_directories[5].size == 0x36C4 and
        pe.data_directories[9].virtual_address == 0x50000 and pe.data_directories[9].size == 0x18 and
        pe.imports("URLMON.DLL") and
        pe.imports("URLMON.DLL", "URLDownloadToFileA") and
        math.entropy(0, filesize) >= 6.6 and math.entropy(0, filesize) <= 6.7 and
        filesize >= 305 * 1024 and filesize <= 315 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
