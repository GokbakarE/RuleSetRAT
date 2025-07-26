rule Buschtrommel_1_0_TNG
{
    meta:
        description = "Detects Buschtrommel_1_0_TNG malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F4 B8 E0 A0 45 00 E8 5C C0 FA FF A1 20 C8 45 00 8B 00 E8 64 47 FE FF 8B 0D E0 C8 45 00 A1 20 C8 45 00 8B 00 8B 15 A0 38 45 00 E8 64 47 FE FF A1 20 C8 45 00 8B 00 E8 D8 47 FE FF E8 EB 95 FA FF 8D 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 00 3C 7A 3E }
        $s1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
        $s2 = "\\Hardware\\Description\\System\\CentralProcessor\\0"
        $s3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s4 = ">$>,>0>4>8><>@>D>H>L>P>T>X>\\>`>d>h>l>p>t>x>|>"
        $s5 = "6165696=6A6E6I6M6Q6U6Y6]6a6e6i6m6q6u6"
        $s6 = "+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|" 
        $s7 = ";$;(;0;4;<;@;H;L;T;X;`;d;l;p;x;|;" 
        $s8 = "EInvalidGraphicOperation"
        $s9 = "CreateToolhelp32Snapshot" 
        $s10 = "9,1NEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEON" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x59660 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0005A260 and//Optional Header's EP 
        uint32(0x130) == 0x0005B000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x5E000 and pe.data_directories[1].size == 0x2344 and
        pe.data_directories[2].virtual_address == 0x69000 and pe.data_directories[2].size == 0x5E00 and
        pe.data_directories[5].virtual_address == 0x63000 and pe.data_directories[5].size == 0x5E44 and
        pe.data_directories[9].virtual_address == 0x62000 and pe.data_directories[9].size == 0x18 and
        pe.imports("netapi32.dll") and
        pe.imports("winmm.dll", "sndPlaySoundA") and
        math.entropy(0, filesize) >= 6.51 and math.entropy(0, filesize) <= 6.61 and
        filesize >= 417 * 1024 and filesize <= 427 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x69600 and
        8 of ($s*)
}
