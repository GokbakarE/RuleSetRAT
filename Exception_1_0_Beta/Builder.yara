rule Exception_1_0_Beta
{
    meta:
        description = "Detects Exception_1_0_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:   
        $EP = { 60 BE 00 ?? 40 00 8D BE 00 ?? FF FF 57 83 CD FF }
        $Overlay = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BE BE BE BE BE BE BE BE BE BE BE BE BE BE BE BE BE }
        $s1 = "GetProcAddress"
        $s2 = "ShellExecuteA"
        $s3 = "InternetOpenA"
        $s4 = "LoadLibraryA"
        $s5 = "KERNEL32.DLL" nocase
        $s6 = "ADVAPI32.dll" nocase
        $s7 = "WININET.dll" nocase
        $s8 = "WSOCK32.dll" nocase
        $s9 = "SHELL32.dll" nocase
        $s10 = "ExitProcess"
    condition:
        pe.is_pe and
        (pe.entry_point == 0x1A80 or pe.entry_point == 0x1AA0)  and
        $EP at (pe.entry_point) and
        (uint32(0x110) == 0x00007680 or uint32(0x118) == 0x000086A0 ) and//Optional Header's EP 
        (uint32(0x120) == 0x00009000 or uint32(0x118) == 0x00008000) and//Optional Header's Base of Data
        (pe.timestamp == 0x409CC16E or pe.timestamp == 0x409CC1F0) and
        (pe.data_directories[1].virtual_address == 0x8000 or pe.data_directories[1].virtual_address == 0x9F10) and pe.data_directories[1].size == 0x1A0 and
        pe.imports("WSOCK32.dll") and
        pe.imports("WININET.dll", "InternetOpenA") and
        math.entropy(0, filesize) >= 6.4 and math.entropy(0, filesize) <= 7.2 and
        filesize >= 7 * 1024 and filesize <= 13 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        (pe.overlay.offset == 0x1E00 or pe.overlay.offset == 0x2E00) and
        9 of ($s*)
}
