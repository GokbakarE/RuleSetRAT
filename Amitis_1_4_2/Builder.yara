import "pe"
import "math"
rule Amitis_1_4_2
{
    meta:
        description = "Detects Amitis_1_4_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 B0 48 00 8D BE 00 60 F7 FF C7 87 10 67 0B 00 99 4C 32 74 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 }
        $s1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s2 = "E0-3AEA-1069-A2D8-08002B30"
        $s3 = "kernel32.dll^GetLongPqNq"
        $s4 = "g,CLSID\\{20D04F"
        $s5 = "23C2$C456$C2$78"
        $s6 = "ANSI_CHARSETDi"
        $s7 = "WWY]\\WlYpZlXt"
        $s8 = "p.h|#G;w85_!"
        $s9 = "CURRENT_USER"
        $s10 = "T!undArrayy"
    condition:
        pe.is_pe and
        pe.entry_point == 0x4BF20 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000D6B20 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xD745C and pe.data_directories[1].size == 0x330 and
        pe.data_directories[2].virtual_address == 0xD7000 and pe.data_directories[2].size == 0x45C and 
        pe.data_directories[9].virtual_address == 0xD6C90 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wsock32.dll", "send") and
        pe.imports("winspool.drv") and
        pe.imports("winspool.drv", "OpenPrinterA") and
        pe.imports("winmm.dll") and
        pe.imports("winmm.dll", "sndPlaySoundA") and
        pe.imports("wininet.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 7.9 and math.entropy(0, filesize) <= 8.0 and
        filesize >= 305 * 1024 and filesize <= 307 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
