rule Slh_2_0
{
    meta:
        description = "Detects Slh_2_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 0F 00 00 00 6A 00 6A 00 49 75 F9 53 B8 B8 FD 00 10 E8 DE 44 FF FF 33 C0 55 68 6C 03 01 10 64 FF 30 64 89 20 68 07 80 00 00 E8 AA 47 FF FF B8 84 03 01 10 E8 BC D2 FF FF 68 98 03 01 10 6A FF 6A 00 E8 02 46 FF FF A3 80 29 01 10 E8 B0 46 FF FF 3D B7 00 00 00 75 1D A1 80 29 01 10 50 E8 66 47 FF FF A1 80 29 01 10 50 E8 B3 45 FF }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\"
        $s3 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s4 = "Toolhelp32ReadProcessMemory"
        $s5 = "InitializeProcessForWsWatch"
        $s6 = "InitializeCriticalSection" 
        $s7 = "8&8.868>8F8N8V8^8f8n8v8~8" 
        $s8 = "7&7.767>7F7N7V7^7f7n7v7~7"
        $s9 = "6&6.666>6F6N6V6^6f6n6v6~6" 
        $s10 = "CreateToolhelp32Snapshot"
    condition:
        pe.is_pe and
        pe.entry_point == 0xF280 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0000FE80 and//Optional Header's EP 
        uint32(0x130) == 0x00011000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x13000 and pe.data_directories[1].size == 0x130C and
        pe.data_directories[2].virtual_address == 0x19000 and pe.data_directories[2].size >= 0x200 and pe.data_directories[2].size <= 0x300 and
        pe.data_directories[5].virtual_address == 0x18000 and pe.data_directories[5].size == 0xEB0 and
        pe.data_directories[9].virtual_address == 0x17000 and pe.data_directories[9].size == 0x18 and
        pe.imports("WS2_32.DLL") and
        pe.imports("kernel32.dll", "OpenThread") and
        math.entropy(0, filesize) >= 6.25 and math.entropy(0, filesize) <= 6.35 and
        filesize >= 70 * 1024 and filesize <= 80 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}