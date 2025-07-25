rule Slh_3_0
{
    meta:
        description = "Detects Slh_3_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 16 00 00 00 6A 00 6A 00 49 75 F9 51 53 B8 C4 1A 01 10 E8 79 27 FF FF 33 C0 55 68 86 22 01 10 64 FF 30 64 89 20 68 E8 03 00 00 E8 95 2A FF FF 68 94 22 01 10 6A FF 6A 00 E8 AF 28 FF FF A3 A0 49 01 10 E8 6D 29 FF FF 3D B7 00 00 00 75 1D A1 A0 49 01 10 50 E8 23 2A FF FF A1 A0 49 01 10 50 E8 60 28 FF FF 6A 00 E8 C9 28 FF FF 68 }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\"
        $s3 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s4 = "Toolhelp32ReadProcessMemory"
        $s5 = ";.<f<m<H=L=P=T=X=\\=`=d=h=l=p=t=x=|="
        $s6 = "InitializeCriticalSection" 
        $s7 = "MakeSureDirectoryPathExists" 
        $s8 = "0&0,0L0T0X0\\0`0d0h0l0p0t0"
        $s9 = "AllowSetForegroundWindow" 
        $s10 = "NoPlugin|extension.dll"
    condition:
        pe.is_pe and
        pe.entry_point == 0x10F94 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00011B94 and//Optional Header's EP 
        uint32(0x130) == 0x00013000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x15000 and pe.data_directories[1].size == 0x13E2 and
        pe.data_directories[2].virtual_address == 0x1C000 and pe.data_directories[2].size >= 0x80 and pe.data_directories[2].size <= 0xFF and
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0x1150 and
        pe.data_directories[9].virtual_address == 0x19000 and pe.data_directories[9].size == 0x18 and
        pe.imports("advpack.dll") and
        pe.imports("urlmon", "URLDownloadToFileA") and
        math.entropy(0, filesize) >= 6.26 and math.entropy(0, filesize) <= 6.36 and
        filesize >= 78 * 1024 and filesize <= 88 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
