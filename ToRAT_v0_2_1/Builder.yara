rule ToRAT_v0_2_1
{
    meta:
        description = "Detects ToRAT_v0_2_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { E8 B5 D0 00 00 E9 7F FE FF FF CC CC CC CC CC CC CC CC CC 57 56 8B 74 24 10 8B 4C 24 14 8B 7C 24 0C 8B C1 8B D1 03 C6 3B FE 76 08 3B F8 0F 82 68 03 00 00 0F BA 25 FC 31 4C 00 01 73 07 F3 A4 E9 17 03 00 00 81 F9 80 00 00 00 0F 82 CE 01 00 00 8B C7 33 C6 A9 0F 00 00 00 75 0E 0F BA 25 24 E3 4B 00 01 0F 82 DA 04 00 00 0F BA 25 FC 31 4C 00 }
        $s1 = "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO" 
        $s2 = "3!3%3)3-3135393=3A3E3I3M3Q3U3Y3]3a3e3i3m3q3u3y3"
        $s3 = "WaitForThreadpoolTimerCallbacks"
        $s4 = "0!0&0,04090?0G0L0R0Z0_0e0m0r0x0"
        $s5 = "Wow64DisableWow64FsRedirection"
        $s6 = "________________________________" 
        $s7 = "JanFebMarAprMayJunJulAugSepOctNovDec" 
        $s8 = "InitializeSecurityDescriptor"
        $s9 = "InitializeCriticalSectionEx" 
        $s10 = "InitiateSystemShutdownExW" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x271CD and
        $EP at (pe.entry_point) and
        uint32(0x138) == 0x00027DCD and//Optional Header's EP 
        uint32(0x140) == 0x0008F000 and//Optional Header's Base of Data
        pe.timestamp == 0x576812D4 and
        pe.data_directories[1].virtual_address == 0xBA44C and pe.data_directories[1].size == 0x17C and
        pe.data_directories[2].virtual_address == 0xC7000 and pe.data_directories[2].size >= 0x37A000 and pe.data_directories[2].size <= 0x37AFFF and 
        pe.data_directories[5].virtual_address == 0x442000 and pe.data_directories[5].size == 0x711C and
        pe.data_directories[6].virtual_address == 0x92BC0 and pe.data_directories[6].size == 0x1C and
        pe.imports("OLEAUT32.dll") and
        pe.imports("COMDLG32.dll", "GetOpenFileNameW") and
        math.entropy(0, filesize) >= 7.78 and math.entropy(0, filesize) <= 7.88 and
        filesize >= 4300 * 1024 and filesize <= 4400 * 1024 and
        9 of ($s*)
}
