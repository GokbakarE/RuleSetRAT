rule Z_dem0n10
{
    meta:
        description = "Detects Z_dem0n10 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "MIT License"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 F0 5B 4A 00 E8 BC 0E F6 FF A1 68 8A 4A 00 8B 00 E8 04 25 FB FF 8B 0D F4 86 4A 00 A1 68 8A 4A 00 8B 00 8B 15 BC B0 49 00 E8 04 25 FB FF A1 68 8A 4A 00 8B 00 E8 78 25 FB FF E8 FB E7 F5 FF 8D 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" 
        $s2 = "System\\CurrentControlSet\\Control\\Print\\Printers"
        $s3 = "from=Z-dem0n&fromemail=Z-dem0n@xxx.net&subject="
        $s4 = "3$3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
        $s5 = "Hardware\\Description\\System\\CentralProcessor\\0"
        $s6 = "system\\CurrentControlSet\\Services\\VxD\\VNETSUP" 
        $s7 = "=)>->1>5>9>=>A>E>I>M>Q>U>Y>]>a>e>i>m>q>u>y>}>" 
        $s8 = ">(>0>4>8><>@>D>H>L>P>T>X>\\>`>d>h>l>p>t>x>|>"
        $s9 = "-----------PASSWORDS----------------------" 
        $s10 = "-----------UINs----------------------" 
    condition:
        pe.is_pe and
        pe.entry_point == 0xA52E0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000A5EE0 and//Optional Header's EP 
        uint32(0x130) == 0x000A6000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xAB000 and pe.data_directories[1].size == 0x2D98 and
        pe.data_directories[2].virtual_address == 0xBA000 and pe.data_directories[2].size == 0x8600 and 
        pe.data_directories[5].virtual_address == 0xB0000 and pe.data_directories[5].size == 0x9DBC and
        pe.data_directories[9].virtual_address == 0xAF000 and pe.data_directories[9].size == 0x18 and
        pe.imports("rasapi32.dll") and
        pe.imports("mpr.dll", "WNetEnumCachedPasswords") and
        math.entropy(0, filesize) >= 6.58 and math.entropy(0, filesize) <= 6.68 and
        filesize >= 752 * 1024 and filesize <= 762 * 1024 and
        9 of ($s*)
}