rule TsuRat_v0_2
{
    meta:
        description = "Detects TsuRat_v0_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 EC 53 56 33 C0 89 45 EC B8 4C F8 43 00 E8 35 69 FC FF BB FC 2B 44 00 33 C0 55 68 8D FA 43 00 64 FF 30 64 89 20 68 E8 03 00 00 E8 48 D2 FC FF 8D 45 EC E8 90 7D FF FF 8B 45 EC E8 90 4D FC FF 50 6A FF 6A 00 E8 4E 6A FC FF 8B F0 85 F6 74 09 E8 3B 6B FC FF 85 C0 74 05 E8 BA 47 FC FF E8 29 BB FF FF A1 08 12 44 00 80 38 00 74 }
        $s1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDIN" nocase
        $s2 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString"
        $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\ProgramFilesDir"
        $s4 = "=!=%=)=-=1=5=9===A=E=I=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s6 = ";$;,;0;4;8;<;@;D;H;L;P;T;X;\\;`;d;h;l;p;t;x;|;" 
        $s7 = "$TMultiReadExclusiveWriteSynchronizer" 
        $s8 = "8$84888@8D8H8L8P8T8X8\\8`8d8h8l8p8t8"
        $s9 = ";!;%;);-;1;5;9;K;c;a=e=i=m=q=u=y=}=" 
        $s10 = "4$4(40444<4@4H4L4T4X4`4d4l4p4x4|4"
    condition:
        pe.is_pe and
        pe.entry_point == 0x3ED9C and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0003F99C and//Optional Header's EP 
        uint32(0x130) == 0x00040000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x43000 and pe.data_directories[1].size == 0x1A5E and
        pe.data_directories[2].virtual_address == 0x4B000 and pe.data_directories[2].size == 0x2128 and 
        pe.data_directories[5].virtual_address == 0x47000 and pe.data_directories[5].size == 0x3578 and
        pe.data_directories[9].virtual_address == 0x46000 and pe.data_directories[9].size == 0x18 and
        pe.imports("AVICAP32.DLL") and
        pe.imports("SHFolder.dll", "SHGetFolderPathA") and
        math.entropy(0, filesize) >= 6.51 and math.entropy(0, filesize) <= 6.61 and
        filesize >= 281 * 1024 and filesize <= 291 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}