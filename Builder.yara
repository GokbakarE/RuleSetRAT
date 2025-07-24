rule Z_dem0n126
{
    meta:
        description = "Detects Z_dem0n126 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "MIT License"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 F8 F7 4A 00 E8 48 73 F5 FF A1 8C 20 4B 00 8B 00 E8 A4 A6 FA FF A1 8C 20 4B 00 8B 00 33 D2 E8 A2 A2 FA FF 8B 0D E4 1C 4B 00 A1 8C 20 4B 00 8B 00 8B 15 C0 18 4A 00 E8 96 A6 FA FF A1 8C 20 4B 00 8B 00 E8 0A A7 FA FF E8 69 4C F5 FF 90 00 00 00 00 00 00 00 00 00 00 00 00 }
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
        pe.entry_point == 0xAEEF0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000AFAF0 and//Optional Header's EP 
        uint32(0x130) == 0x000B0000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xB5000 and pe.data_directories[1].size == 0x2E08 and
        pe.data_directories[2].virtual_address == 0xC5000 and pe.data_directories[2].size == 0x7000 and 
        pe.data_directories[5].virtual_address == 0xBA000 and pe.data_directories[5].size == 0xA72C and
        pe.data_directories[9].virtual_address == 0xB9000 and pe.data_directories[9].size == 0x18 and
        pe.imports("rasapi32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.59 and math.entropy(0, filesize) <= 6.69 and
        filesize >= 786 * 1024 and filesize <= 796 * 1024 and
        9 of ($s*)
}