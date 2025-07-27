rule AntiLamer_BackDoor_v1_1
{
    meta:
        description = "Detects AntiLamer_BackDoor_v1_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 70 44 00 8D BE 00 A0 FB FF C7 87 D0 C4 05 00 0F C4 C9 25 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 }
        //Found overlay hex are; 0D 0A 0D 0A  , 0D 0A   ,    0D 0A 0D 0A 0D 0A         
        $s1 = "TWARE\\Borland\\Delphi\\RTL"
        $s2 = "WNetEnumCachedPasswords"
        $s3 = "I_CHARSETDEFAULT5"
        $s4 = "GetLongPathNameA&"
        $s5 = "#t&<0t%<.t,<,t3"
        $s6 = "PORT_(^.SCJ_LI"
        $s7 = "GetProcAddress"
        $s8 = "sndPlaySoundA"
        $s9 = "ShellExecuteA"
        $s10 = "LMNO)STUVWXYZ"
    condition:
        pe.is_pe and
        pe.entry_point >= 0x28C00 and pe.entry_point <= 0x28D00 and
        $EP at (pe.entry_point) and
        uint32(0x128) >= 0x0006F800 and uint32(0x128) <= 0x0006F890 and    //Optional Header's EP 
        uint32(0x130) == 0x00070000 and 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x70A04 and pe.data_directories[1].size == 0x2F0 and
        pe.data_directories[2].virtual_address == 0x70000 and pe.data_directories[2].size == 0xA04 and
        pe.data_directories[9].virtual_address >= 0x6F900 and pe.data_directories[9].virtual_address <= 0x6F9F0 and 
        pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wsock32.dll", "send") and
        pe.imports("winspool.drv") and
        pe.imports("winspool.drv", "OpenPrinterA") and
        pe.imports("winmm.dll") and
        pe.imports("winmm.dll", "sndPlaySoundA") and
        pe.imports("rasapi32.dll") and
        pe.imports("rasapi32.dll", "RasHangUpA") and
        math.entropy(0, filesize) >= 7.85 and math.entropy(0, filesize) <= 7.9 and
        filesize >= 165 * 1024 and filesize <= 170 * 1024 and
        //some samples have overlay, some not have.
        8 of ($s*)
}