rule Bersek_1_0
{
    meta:
        description = "Detects Bersek_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { BE 00 70 42 00 8D BE 00 A0 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 }
        $Overlay = { 00 E0 00 0E 21 0B 01 06 00 00 C0 00 00 00 10 00 00 00 C0 03 00 40 8E 04 00 00 D0 03 00 00 90 04 00 00 00 00 10 00 10 00 00 00 02 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 A0 04 00 00 10 00 00 00 00 00 00 02 00 00 00 00 00 10 00 00 10 00 00 00 00 10 00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 90 04 }
        $s1 = "LoadLibraryAopenrSOFTWA"
        $s2 = "RE\\rcs\\Berzkpath$[unw"
        $s3 = "RE\\Microsoft\\Wiow"
        $s4 = "!o&RIGHUP]7LEFT"
        $s5 = "RLSHIFTAB_Capf"
        $s6 = "GetProcAddress"
        $s7 = "Toolhelp)Snap"
        $s8 = "ShellExecuteA" 
        $s9 = "CloseHandleO,"
        $s10 = "owunikeygeff"
    condition:
        pe.is_pe and
        pe.entry_point == 0x6ED1 and
        $EP at (pe.entry_point) and
        uint32(0x68) == 0x0002DCD1 and//Optional Header's EP 
        uint32(0x70) == 0x0002E000 and//Optional Header's Base of Data
        pe.timestamp == 0x4484B45F and
        pe.data_directories[1].virtual_address == 0x2E000 and pe.data_directories[1].size == 0x114 and
        pe.data_directories[2].virtual_address == 0x0 and pe.data_directories[2].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("ADVAPI32.dll") and
        pe.imports("ADVAPI32.dll", "RegCloseKey") and
        pe.imports("SHELL32.dll") and
        pe.imports("SHELL32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 7.83 and math.entropy(0, filesize) <= 7.88 and
        filesize >= 75 * 1024 and filesize <= 80 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        9 of ($s*)
}
