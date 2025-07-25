rule Z_dem0n12
{
    meta:
        description = "Detects Z_dem0n12 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 50 BA 4A 00 E8 EC B0 F5 FF A1 34 E0 4A 00 8B 00 E8 18 C7 FA FF A1 34 E0 4A 00 8B 00 33 D2 E8 16 C3 FA FF 8B 0D A8 DC 4A 00 A1 34 E0 4A 00 8B 00 8B 15 A4 F6 49 00 E8 0A C7 FA FF A1 34 E0 4A 00 8B 00 E8 7E C7 FA FF E8 0D 8A F5 FF 90 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" 
        $s2 = "System\\CurrentControlSet\\Control\\Print\\Printers"
        $s3 = "from=Z-dem0n&fromemail=Z-dem0n@xxx.net&subject="
        $s4 = "TAdvancedMenuDrawItemEvent"
        $s5 = "Hardware\\Description\\System\\CentralProcessor\\0"
        $s6 = "system\\CurrentControlSet\\Services\\VxD\\VNETSUP" 
        $s7 = "--------------------------------------------" 
        $s8 = "=,=0=4=8=<=@=D=H=L=P=T=X=\\=`=d=h=l=p=t=x=|="
        $s9 = "-----------PASSWORDS----------------------" 
        $s10 = "-----------UINs----------------------" 
    condition:
        pe.is_pe and
        pe.entry_point == 0xAB140 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000ABD40 and//Optional Header's EP 
        uint32(0x130) == 0x000AC000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xB1000 and pe.data_directories[1].size == 0x2DB6 and
        pe.data_directories[2].virtual_address == 0xC1000 and pe.data_directories[2].size == 0x6C00 and 
        pe.data_directories[5].virtual_address == 0xB6000 and pe.data_directories[5].size == 0xA210 and
        pe.data_directories[9].virtual_address == 0xB5000 and pe.data_directories[9].size == 0x18 and
        pe.imports("rasapi32.dll") and
        pe.imports("iphlpapi.dll", "GetNetworkParams") and
        math.entropy(0, filesize) >= 6.58 and math.entropy(0, filesize) <= 6.68 and
        filesize >= 768 * 1024 and filesize <= 778 * 1024 and
        9 of ($s*)
}
