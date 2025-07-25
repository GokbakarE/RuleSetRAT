rule Solitude_RAT_1_0
{
    meta:
        description = "Detects Solitude_RAT_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 06 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 B8 24 76 40 00 E8 18 B3 FF FF 33 C0 55 68 78 79 40 00 64 FF 30 64 89 20 E8 CD B4 FF FF E8 4C FE FF FF E8 5B FD FF FF 8D 45 EC 8B 15 B8 80 40 00 E8 75 A5 FF FF 8B 45 EC E8 11 FA FF FF 84 C0 75 07 6A 00 E8 5A B4 FF FF BA 88 79 40 00 B8 B0 80 40 00 E8 9F F9 FF FF 8B D8 B8 18 A0 40 00 }
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
        $s2 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot"
        $s3 = "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet003\\Control\\SafeBoot"
        $s4 = "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\SafeBoot"
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s6 = "6(6,6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" 
        $s7 = "Software\\Classes\\http\\shell\\open\\command\\" 
        $s8 = "htmlfile\\shell\\open\\command\\"
        $s9 = "Toolhelp32ReadProcessMemory" 
        $s10 = "http\\shell\\open\\command\\"
    condition:
        pe.is_pe and
        pe.entry_point == 0x6A9C and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0000769C and//Optional Header's EP 
        uint32(0x130) == 0x00008000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xB000 and pe.data_directories[1].size == 0x930 and
        pe.data_directories[2].virtual_address == 0xF000 and pe.data_directories[2].size >= 0x26000 and pe.data_directories[2].size <= 0x26FFF and
        pe.data_directories[5].virtual_address == 0xE000 and pe.data_directories[5].size == 0x574 and
        pe.data_directories[9].virtual_address == 0xD000 and pe.data_directories[9].size == 0x18 and
        pe.imports("shell32.dll") and
        pe.imports("user32.dll", "CharNextA") and
        math.entropy(0, filesize) >= 7.79 and math.entropy(0, filesize) <= 7.89 and
        filesize >= 181 * 1024 and filesize <= 191 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
