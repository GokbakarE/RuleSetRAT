rule FeRAT_v1_00
{
    meta:
        description = "Detects FeRAT_v1_00 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F4 B8 20 21 45 00 E8 68 40 FB FF A1 A0 3E 45 00 8B 00 E8 10 10 FF FF 8B 0D 8C 3F 45 00 A1 A0 3E 45 00 8B 00 8B 15 D0 C5 44 00 E8 10 10 FF FF A1 A0 3E 45 00 8B 00 E8 84 10 FF FF E8 C3 15 FB FF 8D 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 0D 0A }
        $s1 = "software\\microsoft\\windows\\currentversion\\electronicCommerce\\UserInfo"
        $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Network\\LanMan\\C"
        $s3 = "50585<5@5D5H5L5P5T5X5\\5`5d5h55696=6A6E6I6M6Q6U6Y6]6a6e6i6"
        $s4 = "http://web.icq.com/whitepages/page_me/1,,,00.html?to="
        $s5 = "\\Hardware\\Description\\System\\CentralProcessor\\0"
        $s6 = "1$1(1,1014181<1@1D1H1L1P1T1X1\\1`1d1h1l1p1t1x1|1"
        $s7 = "System\\CurrentControlSet\\Services\\VxD\\VNETSUP\\"
        $s8 = "&from=ONLINE&fromemail=notify@ayf.com&body="
        $s9 = "7$7(787@7D7H7L7P7T7X7\\7`7d7h7l7p7t7x7|7"
        $s10 = "6(686@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6"
    condition:
        pe.is_pe and
        pe.entry_point == 0x51678 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00052278 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x56000 and pe.data_directories[1].size == 0x253A and
        pe.data_directories[2].virtual_address == 0x61000 and pe.data_directories[2].size == 0x3C00 and
        pe.data_directories[5].virtual_address == 0x5B000 and pe.data_directories[5].size == 0x5708 and
        pe.imports("urlmon.dll") and
        pe.imports("urlmon.dll", "URLDownloadToFileA") and
        pe.imports("netapi32.dll") and
        pe.imports("netapi32.dll", "Netbios") and
        pe.imports("ole32.dll") and
        pe.imports("ole32.dll", "IsEqualGUID") and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.5 and math.entropy(0, filesize) <= 6.6 and
        filesize >= 376 * 1024 and filesize <= 378 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x5E600 and
        8 of ($s*)
}
