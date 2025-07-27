import "pe"
import "math"
rule Alusinus_RAT_v0_9
{
    meta:
        description = "Detects Alusinus_RAT_v0_9 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 60 46 00 8D BE 00 B0 F9 FF 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 28 8B 1E 83 EE FC 11 DB 72 1F 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 EB 52 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 46 }
        
        $s1 = "|rrrrxtplrrrrhd`\\rrrrXTPL99"
        $s2 = "SOFTWARE\\Borland\\Delphi\\RT"
        $s3 = "NtUnmapViewOfSection"
        $s4 = "GetLongPathNameAbq"
        $s5 = "ZwUnmapViewOfS"
        $s6 = "VirtualProtect" 
        $s7 = "advapi32.dll" nocase 
        $s8 = "GetProcAddress"
        $s9 = "KERNEL32.DLL" nocase  
        $s10 = "RegCloseKey"
    condition:
        pe.is_pe and
        pe.entry_point == 0x47960 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000AD560 and//Optional Header's EP 
        uint32(0x130) == 0x000AE000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xAE314 and pe.data_directories[1].size == 0x1C0 and
        pe.data_directories[2].virtual_address == 0xAE000 and pe.data_directories[2].size == 0x314 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[9].virtual_address == 0xAD708 and pe.data_directories[9].size == 0x18 and
        pe.imports("oleaut32.dll") and
        pe.imports("ntdll.dll", "NtUnmapViewOfSection") and
        math.entropy(0, filesize) >= 7.88 and math.entropy(0, filesize) <= 7.98 and
        filesize >= 283 * 1024 and filesize <= 293 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}
