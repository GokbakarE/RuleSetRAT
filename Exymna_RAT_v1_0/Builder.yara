rule Exymna_RAT_v1_0
{
    meta:
        description = "Detects Exymna_RAT_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "System.Runtime.CompilerServices"
        $s2 = "WrapNonExceptionThrows"
        $s3 = "DllImportAttribute"
        $s4 = "v2.0.50727"
        $s5 = "OpenSubKey"
        $s6 = "output.exe" 
        $s7 = "GetProcesses" 
        $s8 = "ReadAllBytes"
        $s9 = "System.Drawing" 
        $s10 = "ProcessStartInfo"
    condition:
        pe.is_pe and
        pe.entry_point >= 0x24A0 and pe.entry_point <= 0x24EE and
        $EP at (pe.entry_point) and
        uint32(0xA8) >= 0x000042A0 and uint32(0xA8) <= 0x000042EE and//Optional Header's EP 
        uint32(0xB0) == 0x00006000 and//Optional Header's Base of Data
        // no specific date //
        pe.data_directories[1].virtual_address >= 0x4200 and pe.data_directories[1].virtual_address <= 0x42FF and
        pe.data_directories[1].size >= 0x40 and pe.data_directories[1].size <= 0x60 and
        pe.data_directories[2].virtual_address == 0x6000 and pe.data_directories[2].size == 0x2A0 and
        pe.data_directories[5].virtual_address == 0x8000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 4.5 and math.entropy(0, filesize) <= 5.0 and
        filesize >= 8 * 1024 and filesize <= 13 * 1024 and 
        pe.overlay.offset == 0x0 and
        7 of ($s*)
}
