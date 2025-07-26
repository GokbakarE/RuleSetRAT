rule Buschtrommel_1_21
{
    meta:
        description = "Detects Buschtrommel_1_21 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 40 46 00 8D BE 00 D0 F9 FF C7 87 D0 44 08 00 A0 F6 58 BA 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 }
        $Overlay = { 00 32 AD AC AF 30 39 3E 30 34 43 42 48 51 65 70 }
        $s1 = "fah348hfajk823rhaksjhfdo8zfhkasfh83fhskjdo2e9jdailwdjowifjowifuwoihoidjafoijfoiwfjoiefjaoisfjeoijfoeifjesoifjeaf"
        $s2 = "09>04CBHQepp}dzgtux573>201;)(+"
        $s3 = "eofk3po03jrpoefjp30j3efofe"
        $s4 = "SOFTWARE\\Borland\\Delph"
        $s5 = "pxDDDDDDDDDDDDDDpx"
        $s6 = "ORT_(^.SCJ_LINESL" 
        $s7 = "RasEnumEntriesA" 
        $s8 = "/f$$336699.bat:"
        $s9 = "3EThreadArray" 
        $s10 = "rasapi32.dll" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x37FB0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0009BBB0 and//Optional Header's EP 
        uint32(0x130) == 0x0009C000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x9CA3C and pe.data_directories[1].size == 0x280 and
        pe.data_directories[2].virtual_address == 0x9C000 and pe.data_directories[2].size == 0xA3C and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[9].virtual_address == 0x9BD20 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("winmm.dll", "sndPlaySoundA") and
        math.entropy(0, filesize) >= 7.80 and math.entropy(0, filesize) <= 7.94 and
        filesize >= 220 * 1024 and filesize <= 260 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x39000 and
        8 of ($s*)
}
