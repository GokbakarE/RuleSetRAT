import "pe"
import "math"
rule AntiLamer_BackDoor_v1_2
{
    meta:
        description = "Detects AntiLamer_BackDoor_v1_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F4 B8 A0 B8 45 00 E8 B0 A8 FA FF A1 80 DB 45 00 8B 00 E8 24 82 FE FF 8B 0D F0 DC 45 00 A1 80 DB 45 00 8B 00 8B 15 7C 69 45 00 E8 24 82 FE FF A1 80 DB 45 00 8B 00 E8 98 82 FE FF E8 0B 7E FA FF 8D 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $EP2 = { 60 BE 00 90 44 00 8D BE 00 80 FB FF C7 87 D0 D4 05 00 DF C3 F6 16 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 }
        //$EP is not packed, $EP2 is packed(UPX)
        $Overlay = { 0D 0A } //Overlay start string
        $s1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "$TMultiReadExclusiveWriteSynchronizer"
        $s3 = "from=ALB&fromemail=Lamer@ALB.COM&subject="
        $s4 = "Software\\Borland\\Delphi\\Locales"
        $s5 = "====================54535"
        //first 5 string is from not packed
        //last 5 string is from packed(UPX)
        $s6 = "TWARE\\Borland\\Delphi\\RTL"
        $s7 = "WNetEnumCachedPasswords"
        $s8 = "GetLongPathNameA&"
        $s9 = "ANSI_CHARSETDEFA"
        $s10 = "#t&<0t%<.t,<,t3"
    condition:
        pe.is_pe and
        (pe.entry_point == 0x5AE50 or pe.entry_point == 0x292B0) and
        ($EP at (pe.entry_point) or $EP2 at (pe.entry_point)) and
        (uint32(0x128) == 0x0005BA50 or uint32(0x128) == 0x00071EB0 ) and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        (pe.data_directories[1].virtual_address == 0x5F000 and pe.data_directories[1].size == 0x2866 or pe.data_directories[1].virtual_address == 0x73A04 and pe.data_directories[1].size == 0x2F0) and
        (pe.data_directories[2].virtual_address == 0x6B000 and pe.data_directories[2].size == 0x3E00 or pe.data_directories[2].virtual_address == 0x73000 and pe.data_directories[2].size == 0xA04) and
        (pe.data_directories[9].virtual_address == 0x72020 and pe.data_directories[9].size == 0x18 or pe.data_directories[9].virtual_address == 0x63000 and pe.data_directories[9].size == 0x18) and
        pe.imports("KERNEL32.DLL") and
        pe.imports("comctl32.dll") and
        pe.imports("mpr.dll") and
        pe.imports("rasapi32.dll") and
        (math.entropy(0, filesize) >= 6.15 and math.entropy(0, filesize) <= 6.25 or math.entropy(0, filesize) >= 7.85 and math.entropy(0, filesize) <= 7.9) and
        (filesize >= 420 * 1024 and filesize <= 425 * 1024 or filesize >= 165 * 1024 and filesize <= 175 * 1024) and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        (pe.overlay.offset == 0x2A400 or pe.overlay.offset == 0x69A00)  and
        5 of ($s*)
}
