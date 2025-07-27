import "pe"
import "math"
rule Acropolis_1_0 
{
    meta:
        description = "Detects Acropolis_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "24-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F4 B8 40 C4 44 00 E8 24 9A FB FF }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
        $s2 = "=$=(=0=4=<=@=H=L=T=X=`=d=l=p=x=|="
        $s3 = "Software\\Borland\\Delphi\\Locales"
        $s4 = ">>?B?F?J?N?R?V?Z?^?b?f?j?n?r?v?"
        $s5 = "2#3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
        $s6 = ";*;/;:;?;D;O;T;Y;d;i;n;y;~;"
        $s7 = "Root=$DefaultWinport.com"
        $s8 = "=&=+=9=B=G=L=Z=c=h=m={="
        $s9 = "4<4D4H4L4P4T4X4\\4`4d4x4"
        $s10 = "0#000B0J0R0Z0b0j0r0z0"
    condition:
        pe.is_pe and
        pe.entry_point == 0x4B9A8 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0004C5A8 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x52000 and pe.data_directories[1].size == 0x1E90 and
        pe.data_directories[2].virtual_address == 0x5B000 and pe.data_directories[2].size == 0x5F200 and 
        pe.data_directories[5].virtual_address == 0x56000 and pe.data_directories[5].size == 0x4940 and
        pe.imports("gdi32.dll", "SetWindowOrgEx") and
        math.entropy(0, filesize) >= 7.5 and math.entropy(0, filesize) <= 7.6 and
        filesize >= 715 * 1024 and filesize <= 717 * 1024 and
        pe.overlay.size == 0 and 
        7 of ($s*)
}
