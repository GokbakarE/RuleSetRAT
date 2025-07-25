rule Vanguard_Remote_Administration_0_1_Beta
{
    meta:
        description = "Detects Vanguard_Remote_Administration_0_1_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 2E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 B0 AF 00 20 E8 5B 76 FF FF BE 30 D9 00 20 33 C0 55 68 84 B7 00 20 64 FF 30 64 89 20 68 07 80 00 00 E8 FE 78 FF FF B8 9C B7 00 20 E8 00 71 FF FF 8B D0 8B C6 B9 E4 00 00 00 E8 E6 7A FF FF E8 89 B0 FF FF 85 C0 75 07 C7 46 20 06 00 00 00 8D 55 EC 8B 46 20 E8 4B BF FF FF 8B 45 EC }
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
        $s2 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\~MHz"
        $s3 = ".SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        $s4 = "SYSTEM\\CurrentControlSet\\Services\\"
        $s5 = "Toolhelp32ReadProcessMemory"
        $s6 = "MakeSureDirectoryPathExists"
        $s7 = "InitializeProcessForWsWatch"
        $s8 = "user32.dll,LockWorkStation"
        $s9 = "UnhandledExceptionFilter"
        $s10 = "]</specialkey>"
    condition:
        pe.is_pe and
        pe.entry_point == 0xA478 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0000B078 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xE000 and pe.data_directories[1].size == 0x109A and
        pe.data_directories[2].virtual_address == 0x13000 and pe.data_directories[2].size == 0x654 and 
        pe.data_directories[9].virtual_address == 0x11000 and pe.data_directories[9].size == 0x18 and
        pe.imports("kernel32.dll") and
        pe.imports("kernel32.dll", "OpenThread") and
        pe.imports("advpack.dll") and
        pe.imports("advpack.dll", "IsNTAdmin") and
        pe.imports("advapi32.dll") and
        pe.imports("advapi32.dll", "QueryServiceConfig2A") and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "SHGetSpecialFolderPathA") and
        pe.imports("user32.dll") and
        pe.imports("user32.dll", "CharNextA") and
        pe.imports("IMAGEHLP.DLL") and
        pe.imports("IMAGEHLP.DLL", "MakeSureDirectoryPathExists") and
        math.entropy(0, filesize) >= 6.1 and math.entropy(0, filesize) <= 6.2 and
        filesize >= 50 * 1024 and filesize <= 52 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        9 of ($s*)
}
