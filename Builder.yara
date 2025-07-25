rule Sinique_1_0
{
    meta:
        description = "Detects Sinique_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 E8 33 C0 89 45 E8 89 45 EC B8 B8 6B 40 00 E8 68 CD FF FF 33 C0 55 68 97 6C 40 00 64 FF 30 64 89 20 8D 55 EC B8 01 00 00 00 E8 19 BA FF FF 8B 45 EC BA AC 6C 40 00 E8 00 C6 FF FF 75 23 8D 45 E8 E8 12 E4 FF FF 8D 45 E8 BA BC 6C 40 00 E8 AD C4 FF FF 8B 45 E8 E8 95 C6 FF FF 50 E8 57 CE FF FF E8 3E EE FF FF E8 09 F3 FF FF E8 }
        $Overlay = { 8F A7 86 82 89 B9 AE A4 F4 F6 F4 F4 F4 F0 F4 FB F4 0B 0B F4 F4 4C F4 F4 F4 F4 F4 F4 F4 B4 F4 EE F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F5 F4 F4 4E E4 F4 FA EB 40 FD 39 D5 4C F5 B8 39 D5 64 64 A0 9C 9D 87 D4 84 86 9B 93 86 95 99 D4 99 81 87 80 D4 96 91 D4 86 81 9A D4 81 9A }
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
        pe.entry_point == 0x6008 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00006C08 and//Optional Header's EP 
        uint32(0x130) == 0x00007000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x9000 and pe.data_directories[1].size == 0x7B4 and
        pe.data_directories[2].virtual_address == 0xD000 and pe.data_directories[2].size == 0xC00 and
        pe.data_directories[5].virtual_address == 0xC000 and pe.data_directories[5].size == 0x64C and
        pe.data_directories[9].virtual_address == 0xB000 and pe.data_directories[9].size == 0x18 and
        pe.imports("kernel32.dll") and
        pe.imports("shell32.dll", "SHGetPathFromIDListA") and
        math.entropy(0, filesize) >= 7.2 and math.entropy(0, filesize) <= 7.3 and
        filesize >= 60 * 1024 and filesize <= 65 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x8200 and
        9 of ($s*)
}