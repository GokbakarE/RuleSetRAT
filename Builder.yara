rule Pandora_RAT_v1_1
{
    meta:
        description = "Detects Pandora_RAT_v1_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "26-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 56 B8 B4 DD 47 00 E8 16 8B F8 FF BB C4 26 48 00 BE 8C 28 48 00 33 C0 55 68 9E E3 47 00 64 FF 30 64 89 20 B2 01 A1 70 31 47 00 E8 D6 59 F8 FF 89 06 68 D0 07 00 00 E8 56 10 F9 FF B8 88 28 48 00 E8 F8 B2 FF FF 84 C0 0F 84 F9 01 00 00 BA F4 26 48 00 B9 64 00 00 00 A1 88 28 48 00 E8 68 B8 FF FF A1 F4 26 48 00 E8 6E F9 }
        $s1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        $s2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\PATHSS"
        $s3 = "8$8,8084888<8@8D8H8L8P8T8X8\\8`8d8h8l8p8t8x8|8"
        $s4 = "1!1%1)1-1115191=1A1E1I1M1Q1U1Y1]1a1e1i1m1q1u1y1}1"
        $s5 = "<(<,<4<8<<<@<D<H<L<P<T<X<\\<`<d<h<l<p<t<x<|<"
        $s6 = "HKEY_CURRENT_USER\\Software\\Microsoft\\MUTSS"
        $s7 = "7>8j899=9A9E9I9M9Q9U9Y9]9a9e9i9m9q9u9y9}9"
        $s8 = "$TMultiReadExclusiveWriteSynchronizer" 
        $s9 = ":$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:" 
        $s10 = ":>:B:F:J:N:R:V:Z:^:b:f:j:n:r:v:z:~:" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x7D4DC and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0007E0DC and //Optional Header's EP 
        uint32(0x130) == 0x0007F000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x83000 and pe.data_directories[1].size == 0x2CD2 and
        pe.data_directories[2].virtual_address == 0x90000 and pe.data_directories[2].size >= 0x53B0 and pe.data_directories[2].size >= 0x53DF and
        pe.data_directories[5].virtual_address == 0x88000 and pe.data_directories[5].size == 0x7250 and
        pe.data_directories[9].virtual_address == 0x87000 and pe.data_directories[9].size == 0x18 and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        pe.imports("ole32.dll") and
        pe.imports("ole32.dll", "CoInitializeEx") and
        pe.imports("ntdll.dll") and
        pe.imports("ntdll.dll", "RtlSetProcessIsCritical") and
        pe.imports("powrprof.dll") and
        pe.imports("powrprof.dll", "IsPwrShutdownAllowed") and
        math.entropy(0, filesize) >= 6.6 and math.entropy(0, filesize) <= 6.7 and
        filesize >= 570 * 1024 and filesize <= 575 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}