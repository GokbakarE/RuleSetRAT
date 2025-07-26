rule DH_Rat_0_3
{
    meta:
        description = "Detects DH_Rat_0_3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 30 F8 61 00 E8 44 05 DE FF A1 60 6E 63 00 8B 00 E8 C8 26 EB FF A1 60 6E 63 00 8B 00 B2 01 E8 F6 43 EB FF 8B 0D 08 71 63 00 A1 60 6E 63 00 8B 00 8B 15 14 71 61 00 E8 BA 26 EB FF A1 60 6E 63 00 8B 00 E8 FE 27 EB FF E8 AD BE DD FF 90 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 5B 00 36 00 33 00 36 00 38 00 36 00 31 00 37 00 35 00 5D 00 35 00 42 00 36 00 39 00 37 00 30 00 }
        $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s2 = "4!4%4)4-4145494=4A4E4I4M4Q4U4Y4]4a4e4i4m4q4u4y4}4"
        $s3 = "=a0CP4IW3IW2HW2HW2HW2HW2HW2HW2HW2HW2HW3IW4IW0CP"
        $s4 = "2$2(2,2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s5 = ">$>(>,>0>4>8><>@>D>H>L>P>T>X>\\>`>d>h>l>p>t>x>|>"
        $s6 = "9$9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s7 = "5&5*5.52565:5>5B5F5J5N5R5V5Z5^579A9H9O9Z9o9v9"
        $s8 = "(EIdAlreadyRegisteredAuthenticationMethod8/R"
        $s9 = "(TCustomGestureEngine.TGestureEngineFlags"
        $s10 = "(EIdAlreadyRegisteredAuthenticationMethod"
    condition:
        pe.is_pe and
        pe.entry_point == 0x228F70 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0022A770 and //Optional Header's EP 
        uint32(0x130) == 0x0022B000 and //Optional Header's Base of Data
        pe.timestamp == 0x52878373 and
        pe.data_directories[1].virtual_address == 0x23E000 and pe.data_directories[1].size == 0x3C1E and
        pe.data_directories[2].virtual_address == 0x26D000 and (pe.data_directories[2].size == 0x1EE48 or pe.data_directories[2].size == 0x20414) and
        pe.data_directories[5].virtual_address == 0x245000 and pe.data_directories[5].size == 0x27150 and
        pe.data_directories[9].virtual_address == 0x244000 and pe.data_directories[9].size == 0x18 and
        pe.imports("winmm.dll") and
        pe.imports("winmm.dll", "mciSendStringW") and
        pe.imports("winspool.drv") and
        pe.imports("winspool.drv", "GetDefaultPrinterW") and
        pe.imports("msimg32.dll") and
        pe.imports("msimg32.dll", "AlphaBlend") and
        math.entropy(0, filesize) >= 6.49 and math.entropy(0, filesize) <= 6.55 and
        filesize >= 2565 * 1024 and filesize <= 2575 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        (pe.overlay.offset == 0x281000 or pe.overlay.offset == 0x27FA00) and
        8 of ($s*)
}
