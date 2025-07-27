rule Alusinus_RAT_v0_3
{
    meta:
        description = "Detects Alusinus_RAT_v0_3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 F0 45 00 8D BE 00 20 FA FF C7 87 C0 20 07 00 98 82 C2 B6 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 A7 C4 08 00 57 83 C3 04 53 68 48 F1 02 00 56 83 C3 04 53 50 C7 03 03 00 00 00 90 90 90 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 78 B8 01 00 00 00 0F B6 4A 02 89 C3 D3 E3 89 D9 }
        
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
        pe.entry_point == 0x2F550 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0008E150 and//Optional Header's EP 
        uint32(0x130) == 0x0008F000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x943D8 and pe.data_directories[1].size == 0x33C and
        pe.data_directories[2].virtual_address == 0x8F000 and pe.data_directories[2].size == 0x53D8 and
        pe.data_directories[5].virtual_address == 0x94714 and pe.data_directories[5].size == 0x10 and
        pe.data_directories[9].virtual_address == 0x8ED40 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 7.78 and math.entropy(0, filesize) <= 7.88 and
        filesize >= 209 * 1024 and filesize <= 219 * 1024 and
        pe.overlay.offset == 0x35A00 and
        8 of ($s*)
}