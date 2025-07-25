rule Trochilus
{
    meta:
        description = "Detects Trochilus malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "27-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 30 91 40 00 33 F6 C6 44 24 14 20 FF 15 30 70 40 00 68 01 80 00 00 FF 15 B4 70 40 00 53 FF 15 7C 72 40 00 6A 08 A3 58 3F 42 00 E8 09 2C 00 00 A3 A4 3E 42 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 58 F4 41 00 FF 15 58 71 40 00 68 }
        $Overlay = { 02 00 00 00 EF BE AD DE 4E 75 6C 6C 73 6F 66 74 }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s2 = "http://nsis.sf.net/NSIS_Error"
        $s3 = "WritePrivateProfileStringA"
        $s4 = "SHGetSpecialFolderLocation"
        $s5 = "LookupPrivilegeValueA"
        $s6 = "GetWindowsDirectoryA"
        $s7 = "WaitForSingleObject"
        $s8 = "MultiByteToWideChar"
        $s9 = "MessageBoxIndirectA"
        $s10 = "GetSystemDirectoryA"
    condition:
        pe.is_pe and
        pe.entry_point == 0x263C and
        $EP at (pe.entry_point) and
        uint32(0x100) == 0x0000323C and//Optional Header's EP 
        uint32(0x108) == 0x00007000 and//Optional Header's Base of Data
        pe.timestamp == 0x4B1AE3C6 and
        pe.data_directories[1].virtual_address == 0x73A4 and pe.data_directories[1].size == 0xB4 and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x6C8 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("VERSION.dll") and
        pe.imports("COMCTL32.dll", "ImageList_Destroy") and
        math.entropy(0, filesize) >= 7.9 and math.entropy(0, filesize) <= 8.0 and
        filesize >= 320 * 1024 and filesize <= 330 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x7E00 and
        9 of ($s*)
}