rule VanToM_RAT_1_4
{
    meta:
        description = "Detects VanToM_RAT_1_4 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        
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
        pe.entry_point >= 0x2A700 and pe.entry_point <= 0x2A7FF and
        $EP at (pe.entry_point) and
        uint32(0xA8) >= 0x0002C500 and uint32(0xA8) <= 0x0002C5FF and//Optional Header's EP 
        uint32(0xB0) == 0x00000000 and//Optional Header's Base of Data
        // no specific date//
        pe.data_directories[1].virtual_address >= 0x2C000 and pe.data_directories[1].virtual_address <= 0x2CFFF and 
        pe.data_directories[1].size >= 0x40 and pe.data_directories[1].size <= 0x60 and
        pe.data_directories[2].virtual_address == 0x2E000 and pe.data_directories[2].size >= 0x3200 and pe.data_directories[2].size <= 0x3300 and
        pe.data_directories[5].virtual_address == 0x32000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.7 and math.entropy(0, filesize) <= 5.9 and
        filesize >= 178 * 1024 and filesize <= 188 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}