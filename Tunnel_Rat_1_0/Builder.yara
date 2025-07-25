rule Tunnel_Rat_1_0
{
    meta:
        description = "Detects Tunnel_Rat_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 EC 33 C0 89 45 EC B8 B0 73 40 00 E8 9B C5 FF FF 33 C0 55 68 FB 74 40 00 64 FF 30 64 89 20 E8 A4 CF FF FF E8 C3 D1 FF FF E8 46 F8 FF FF E8 35 F7 FF FF 8B 15 E8 9B 40 00 A1 E4 9B 40 00 E8 CD F0 FF FF 33 C9 BA 10 75 40 00 B8 02 00 00 80 E8 98 CC FF FF 8D 45 EC E8 88 EF FF FF 8D 45 EC BA 80 75 40 00 E8 33 BD FF FF 8B 45 EC }
        $s1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall" 
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        $s4 = "187<7@7D7H7L7P7T7X7\\7`7d7h7l7p7t7x7|7"
        $s5 = "0123456789abcdefghijklmnopqrstuvxyz"
        $s6 = "E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E" 
        $s7 = "InitializeCriticalSection" 
        $s8 = ";&;.;6;>;F;N;V;^;f;n;v;~;"
        $s9 = "UnhandledExceptionFilter" 
        $s10 = "System32\\drivers\\Pws.dat"
    condition:
        pe.is_pe and
        pe.entry_point == 0x6850 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00007450 and//Optional Header's EP 
        uint32(0x130) == 0x00008000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xA000 and pe.data_directories[1].size == 0x664 and
        pe.data_directories[2].virtual_address == 0xE000 and pe.data_directories[2].size == 0x3D800 and 
        pe.data_directories[5].virtual_address == 0xD000 and pe.data_directories[5].size == 0x78C and
        pe.data_directories[9].virtual_address == 0xC000 and pe.data_directories[9].size == 0x18 and
        pe.imports("kernel32.dll") and
        pe.imports("shell32.dll", "FindExecutableA") and
        math.entropy(0, filesize) >= 7.24 and math.entropy(0, filesize) <= 7.34 and
        filesize >= 274 * 1024 and filesize <= 284 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
