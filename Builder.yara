rule OrionRAT_0_9
{
    meta:
        description = "Detects OrionRAT_0_9 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "26-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 56 B8 D4 6F 44 00 E8 9E F8 FB FF BB 98 5B 47 00 BE 60 5D 47 00 33 C0 55 68 9E 74 44 00 64 FF 30 64 89 20 B2 01 A1 48 CD 43 00 E8 42 CA FB FF 89 06 68 D0 07 00 00 E8 BA 72 FC FF B8 5C 5D 47 00 E8 E0 BC FF FF 84 C0 0F 84 F9 01 00 00 BA C8 5B 47 00 B9 64 00 00 00 A1 5C 5D 47 00 E8 A8 BD FF FF A1 C8 5B 47 00 E8 C2 FA }
        $s1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        $s2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\PATHSS"
        $s3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\MUTSS"
        $s4 = "8,84888<8@8D8H8L8P8T8X8\\8`8d8h8l8p8t8x8|8"
        $s5 = "$TMultiReadExclusiveWriteSynchronizer"
        $s6 = "4,4<4D4H4L4P4T4X4\\4`4d4h4l4p4t4x4|4"
        $s7 = "=$=(=0=4=<=@=H=L=T=X=`=d=l=p=x=|="
        $s8 = "\\Mozilla\\Firefox\\profiles.ini" nocase
        $s9 = "sqlite3_reset_auto_extension" nocase
        $s10 = "sqlite3_create_collation_v2" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x465D4 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000471D4 and//Optional Header's EP 
        uint32(0x130) == 0x00048000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x76000 and pe.data_directories[1].size == 0x1E88 and
        pe.data_directories[2].virtual_address == 0x7E000 and pe.data_directories[2].size >= 0x1C00  and pe.data_directories[2].size <= 0x1CFF  and
        pe.data_directories[5].virtual_address == 0x7A000 and pe.data_directories[5].size == 0x3C38 and
        pe.data_directories[9].virtual_address == 0x79000 and pe.data_directories[9].size == 0x18 and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        pe.imports("kernel32.dll") and
        pe.imports("kernel32.dll", "GetProcAddress") and
        pe.imports("SHFolder.dll") and
        pe.imports("SHFolder.dll", "SHGetFolderPathA") and
        pe.imports("crypt32.dll") and
        pe.imports("crypt32.dll", "CryptUnprotectData") and
        math.entropy(0, filesize) >= 7.15 and math.entropy(0, filesize) <= 7.30 and
        filesize >= 480 * 1024 and filesize <= 500 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}