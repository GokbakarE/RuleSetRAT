rule VanToM_RAT_1_3
{
    meta:
        description = "Detects VanToM_RAT_1_3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 58 F0 42 00 00 00 00 00 00 00 00 00 2C F0 02 00 00 00 00 00 00 00 00 00 D3 28 A2 52 00 00 00 00 02 00 00 00 44 00 00 00 7C F0 02 00 7C D2 02 00 52 53 44 53 63 3A 68 0A 5B 90 8D 48 90 D1 96 0A 88 36 A9 28 01 00 00 00 43 3A 5C 55 73 65 72 73 5C 56 61 6E 54 6F 4D 5C 44 65 73 6B 74 6F 70 5C 56 61 6E 54 6F 4D 20 52 41 54 5C 53 74 75 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s2 = "$D8D715A3-6E5E-11D0-B3F0-00AA003761C5"
        $s3 = "$C6E13380-30AC-11d0-A18C-00A0C9118956"
        $s4 = "$C6E13340-30AC-11d0-A18C-00A0C9118956"
        $s5 = "$B196B28B-BAB4-101A-B69C-00AA00341D07"
        $s6 = "$a2104830-7c70-11cf-8bce-00aa00a3f1a6" 
        $s7 = "$9e5530c5-7034-48b4-bb46-0b8a6efc8e36" 
        $s8 = "$93E5A4E0-2D50-11d2-ABFA-00A0C9C6E38D"
        $s9 = "$670d1d20-a068-11d0-b3f0-00aa003761c5" 
        $s10 = "$56a868b3-0ad4-11ce-b03a-0020af0ba770"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2D24A and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002F04A and//Optional Header's EP 
        uint32(0xB0) == 0x00030000 and//Optional Header's Base of Data
        pe.timestamp == 0x52A228D3 and
        pe.data_directories[1].virtual_address == 0x2EFFC and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x30000 and pe.data_directories[2].size == 0x3251 and
        pe.data_directories[5].virtual_address == 0x34000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x2F060 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.8 and math.entropy(0, filesize) <= 5.9 and
        filesize >= 189 * 1024 and filesize <= 199 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x30A00 and
        8 of ($s*)
}
