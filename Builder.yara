rule Furax_1_0b2
{
    meta:
        description = "Detects Furax_1_0b2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 6A FF 68 38 B3 40 00 68 D8 A4 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 F0 B1 40 00 59 83 0D E4 F9 40 00 FF 83 0D E8 F9 40 00 FF FF 15 EC B1 40 00 8B 0D DC F9 40 00 89 08 FF 15 E8 B1 40 00 8B 0D D8 F9 40 00 89 08 A1 E4 B1 40 00 8B 00 A3 E0 F9 40 00 E8 22 01 00 00 39 }
        $s1 = ">#>(>.>2>7><>B>F>K>P>V>Z>_>d>"
        $s2 = "InitializeCriticalSection"
        $s3 = "0,030:0A0H0O0V0]0d0k0r0y0"
        $s4 = "KeServiceDescriptorTable"
        $s5 = "GetWindowThreadProcessId"
        $s6 = "NtAllocateVirtualMemory" 
        $s7 = "NtSetInformationProcess" 
        $s8 = "DeleteCriticalSection"
        $s9 = "NtWriteVirtualMemory" 
        $s10 = "??1type_info@@UAE@XZ" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x9746 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0000A346 and//Optional Header's EP 
        uint32(0x130) == 0x0000B000 and//Optional Header's Base of Data
        pe.timestamp == 0x42FF0DC9 and
        pe.data_directories[1].virtual_address == 0xB5B8 and pe.data_directories[1].size == 0xDC and
        pe.data_directories[2].virtual_address == 0x10000 and pe.data_directories[2].size == 0xF08 and
        pe.data_directories[5].virtual_address == 0x11000 and pe.data_directories[5].size == 0x7E4 and
        pe.data_directories[12].virtual_address == 0xB000 and pe.data_directories[12].size == 0x31C and
        pe.imports("MSVCRT.dll") and
        pe.imports("MSVCRT.dll", "_CxxThrowException") and
        pe.imports("SHLWAPI.dll") and
        pe.imports("SHLWAPI.dll", "SHDeleteKeyA") and
        pe.imports("WSOCK32.dll") and
        math.entropy(0, filesize) >= 6.4 and math.entropy(0, filesize) <= 6.7 and
        filesize >= 52 * 1024 and filesize <= 61 * 1024 and
        //no specified overlay string, all random 
        pe.overlay.offset == 0xD800 and
        9 of ($s*)
}