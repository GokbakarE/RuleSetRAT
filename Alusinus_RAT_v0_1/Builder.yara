rule Alusinus_RAT_v0_1
{
    meta:
        description = "Detects Alusinus_RAT_v0_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 70 41 00 8D BE 00 A0 FE FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 4F E6 01 00 57 83 C3 04 53 68 BA 92 00 00 56 83 C3 04 53 50 C7 03 03 00 00 00 90 90 90 90 90 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 78 B8 01 00 00 00 0F B6 }
        
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
        pe.entry_point == 0x96C0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000202C0 and//Optional Header's EP 
        uint32(0x130) == 0x00021000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x22350 and pe.data_directories[1].size == 0x1C0 and
        pe.data_directories[2].virtual_address == 0x21000 and pe.data_directories[2].size == 0x1350 and
        pe.data_directories[5].virtual_address == 0x22510 and pe.data_directories[5].size == 0x10 and
        pe.data_directories[9].virtual_address == 0x20EA8 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 7.59 and math.entropy(0, filesize) <= 7.69 and
        filesize >= 41 * 1024 and filesize <= 51 * 1024 and
        pe.overlay.offset == 0xBA00 and
        8 of ($s*)
}
