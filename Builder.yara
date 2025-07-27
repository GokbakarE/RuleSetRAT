rule Alusinus_RAT_v0_6
{
    meta:
        description = "Detects Alusinus_RAT_v0_6 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 30 46 00 8D BE 00 E0 F9 FF C7 87 C0 60 07 00 D4 13 52 FA 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 4B 17 09 00 57 83 C3 04 53 68 EF 00 03 00 56 83 C3 04 53 50 C7 03 03 00 00 00 90 90 90 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 }
        
        $s1 = "InternetGetConnectedState"
        $s2 = "xuFuncionesEncriptacion"
        $s3 = "uDatosOrdenador"
        $s4 = "VirtualProtect"
        $s5 = "GetProcAddress"
        $s6 = "VirtualAlloc" 
        $s7 = "oleaut32.dll" nocase 
        $s8 = "LoadLibraryA"
        $s9 = "KERNEL32.DLL" nocase  
        $s10 = "VirtualFree"
    condition:
        pe.is_pe and
        pe.entry_point == 0x30500 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00093100 and//Optional Header's EP 
        uint32(0x130) == 0x00094000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x99408 and pe.data_directories[1].size == 0x380 and
        pe.data_directories[2].virtual_address == 0x94000 and pe.data_directories[2].size == 0x5408 and
        pe.data_directories[5].virtual_address == 0x99788 and pe.data_directories[5].size == 0x10 and
        pe.data_directories[9].virtual_address == 0x93CF0 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 7.79 and math.entropy(0, filesize) <= 7.89 and
        filesize >= 213 * 1024 and filesize <= 223 * 1024 and
        pe.overlay.offset == 0x36A00 and
        8 of ($s*)
}