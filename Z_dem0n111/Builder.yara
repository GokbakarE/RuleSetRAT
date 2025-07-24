rule Z_dem0n111
{
    meta:
        description = "Detects Z_dem0n111 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "MIT License"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 B8 8C 4A 00 E8 64 DE F5 FF A1 EC BF 4A 00 8B 00 E8 64 F4 FA FF A1 EC BF 4A 00 8B 00 33 D2 E8 62 F0 FA FF 8B 0D 78 BC 4A 00 A1 EC BF 4A 00 8B 00 8B 15 8C E9 49 00 E8 56 F4 FA FF A1 EC BF 4A 00 8B 00 E8 CA F4 FA FF E8 95 B7 F5 FF 90 00 00 00 00 00 00 00 00 00 00 00 00 }
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
        pe.entry_point == 0xA83B8 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000A8FB8 and//Optional Header's EP 
        uint32(0x130) == 0x000AA000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xAF000 and pe.data_directories[1].size == 0x2D16 and
        pe.data_directories[2].virtual_address == 0xBF000 and pe.data_directories[2].size == 0x8600 and 
        pe.data_directories[5].virtual_address == 0xB4000 and pe.data_directories[5].size == 0xA008 and
        pe.data_directories[9].virtual_address == 0xB3000 and pe.data_directories[9].size == 0x18 and
        pe.imports("rasapi32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.59 and math.entropy(0, filesize) <= 6.69 and
        filesize >= 763 * 1024 and filesize <= 773 * 1024 and
        9 of ($s*)
}
