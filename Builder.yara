rule FunFucker_0_8_Alpha
{
    meta:
        description = "Detects FunFucker_0_8_Alpha malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 78 8A 49 00 E8 34 D6 F6 FF 33 C0 55 68 BB 90 49 00 64 FF 30 64 89 20 B2 01 A1 C0 7B 49 00 E8 32 A6 F6 FF A3 D8 0F 4A 00 6A 00 B9 F4 89 49 00 B2 01 A1 04 7F 49 00 E8 2A EF FF FF 6A 01 E8 8F 4E F7 FF A1 D8 0F 4A 00 E8 AD EB FF FF EB ED 33 C0 5A 59 59 64 89 10 68 C2 90 49 00 C3 E9 8C AD F6 FF EB F8 E8 B1 B2 F6 FF 90 }
        $Overlay = { 53 4F 21 23 44 59 4E 44 4E 53 B6 }
        $s1 = "Extended_UNIX_Code_Fixed_Width_for_Japanese"
        $s2 = "C:\\build\\indy10VCL\\Lib\\Core\\IdIOHandler.pas"
        $s3 = "(EIdAlreadyRegisteredAuthenticationMethod"
        $s4 = "C:\\build\\indy10VCL\\Lib\\System\\IdStack.pas"
        $s5 = "%EIdSocksUDPNotSupportedBySOCKSVersion"
        $s6 = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        $s7 = "9(9094989<9@9D9H9L9P9`9y9"
        $s8 = "PC-Multilingual-850+euro"
        $s9 = "C:\\build\\indy10VCL\\Lib\\Protocols\\IdCoder00E.pas"
        $s10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        pe.is_pe and
        pe.entry_point == 0x98458 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00099058 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xA1000 and pe.data_directories[1].size == 0x2634 and
        pe.data_directories[2].virtual_address == 0xB2000 and pe.data_directories[2].size == 0x7600 and
        pe.data_directories[5].virtual_address == 0xA6000 and pe.data_directories[5].size == 0xB344 and
        pe.imports("user32.dll") and
        pe.imports("user32.dll", "BlockInput") and
        pe.imports("WS2_32.DLL") and
        pe.imports("WS2_32.DLL", "ioctlsocket") and
        pe.imports("winmm.dll") and
        pe.imports("winmm.dll", "mciSendStringA") and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.5 and math.entropy(0, filesize) <= 6.6 and
        filesize >= 713 * 1024 and filesize <= 715 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0xB2800 and
        8 of ($s*)
}