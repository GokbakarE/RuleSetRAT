rule Furax_1_0b3
{
    meta:
        description = "Detects Furax_1_0b3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 6A FF 68 40 B3 40 00 68 38 A9 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 FC B1 40 00 59 83 0D 64 FA 40 00 FF 83 0D 68 FA 40 00 FF FF 15 F8 B1 40 00 8B 0D 5C FA 40 00 89 08 FF 15 F4 B1 40 00 8B 0D 58 FA 40 00 89 08 A1 F0 B1 40 00 8B 00 A3 60 FA 40 00 E8 98 9C FF FF 39 }
        
        $s1 = "0+1<1I1M1S1Z1_1e1i1n1s1y1}1"
        $s2 = "InitializeCriticalSection"
        $s3 = "GetDeviceDriverBaseNameA"
        $s4 = "KeServiceDescriptorTable"
        $s5 = "GetWindowThreadProcessId"
        $s6 = "CreateToolhelp32Snapshot" 
        $s7 = "6+6/63676;6?6C6G6K6i6" 
        $s8 = "SetCurrentDirectoryA"
        $s9 = "??1type_info@@UAE@XZ" 
        $s10 = "WaitForSingleObject" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x9BA6 and
        $EP at (pe.entry_point) and
        uint32(0x120) == 0x0000A7A6 and//Optional Header's EP 
        uint32(0x128) == 0x0000B000 and//Optional Header's Base of Data
        pe.timestamp == 0x430E2B79 and
        pe.data_directories[1].virtual_address == 0xB5C0 and pe.data_directories[1].size == 0xDC and
        pe.data_directories[2].virtual_address == 0x10000 and pe.data_directories[2].size == 0xF08 and
        pe.data_directories[5].virtual_address == 0x11000 and pe.data_directories[5].size == 0x810 and
        pe.data_directories[12].virtual_address == 0xB000 and pe.data_directories[12].size == 0x328 and
        pe.imports("MSVCRT.dll") and
        pe.imports("MSVCRT.dll", "_CxxThrowException") and
        pe.imports("SHLWAPI.dll") and
        pe.imports("SHLWAPI.dll", "SHDeleteKeyA") and
        pe.imports("WSOCK32.dll") and
        math.entropy(0, filesize) >= 6.4 and math.entropy(0, filesize) <= 6.7 and
        filesize >= 54 * 1024 and filesize <= 61 * 1024 and
        //no specified overlay string, all random 
        pe.overlay.offset == 0xDE00 and
        9 of ($s*)
}
