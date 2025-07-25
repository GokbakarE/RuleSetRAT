rule Slh
{
    meta:
        description = "Detects Slh malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 0F 00 00 00 6A 00 6A 00 49 75 F9 51 53 B8 BC 94 01 10 E8 C1 B0 FE FF 33 C0 55 68 CA 9A 01 10 64 FF 30 64 89 20 8D 45 E8 E8 AB 9C FF FF 8B 45 E8 8D 55 EC E8 D0 8D FF FF 8B 55 EC B8 94 DD 01 10 E8 83 A0 FE FF 8D 55 E0 33 C0 E8 8D 91 FE FF 8B 45 E0 8D 55 E4 E8 AE 8D FF FF 8B 45 E4 8B 15 94 DD 01 10 E8 F8 A2 FE FF 74 58 8D 55 }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "!0%0)0-0105090=0A0E0I0M0Q0U0Y0]0a0e0i0m0q0v0"
        $s3 = "||||||||||||||||||||||||||||"
        $s4 = "Toolhelp32ReadProcessMemory"
        $s5 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s6 = "InitializeProcessForWsWatch" 
        $s7 = "SHGetSpecialFolderLocation" 
        $s8 = "InitializeCriticalSection"
        $s9 = ";&;.;6;>;F;N;V;^;f;n;v;~;" 
        $s10 = "UnhandledExceptionFilter"
    condition:
        pe.is_pe and
        pe.entry_point == 0x189A4 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000195A4 and//Optional Header's EP 
        uint32(0x130) == 0x0001A000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x1E000 and pe.data_directories[1].size == 0x1338 and
        pe.data_directories[2].virtual_address == 0x24000 and pe.data_directories[2].size >= 0x900 and pe.data_directories[2].size <= 0xA00 and
        pe.data_directories[5].virtual_address == 0x22000 and pe.data_directories[5].size == 0x1538 and
        pe.data_directories[9].virtual_address == 0x21000 and pe.data_directories[9].size == 0x18 and
        pe.imports("WS2_32.DLL") and
        pe.imports("avicap32.dll", "capCreateCaptureWindowA") and
        math.entropy(0, filesize) >= 6.44 and math.entropy(0, filesize) <= 6.49 and
        filesize >= 120 * 1024 and filesize <= 125 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}