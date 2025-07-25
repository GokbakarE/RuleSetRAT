rule VanToM_RAT_1_0
{
    meta:
        description = "Detects VanToM_RAT_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 1C 49 43 00 00 00 00 00 00 00 00 00 F0 48 03 00 00 00 00 00 00 00 00 00 38 4D C1 51 00 00 00 00 02 00 00 00 82 00 00 00 40 49 03 00 40 2B 03 00 52 53 44 53 06 ED BD 14 8B 58 7D 43 A3 59 F5 97 71 14 B6 35 01 00 00 00 43 3A 5C 55 73 65 72 73 5C 56 61 6E 54 6F 4D 5C 44 6F 77 6E 6C 6F 61 64 73 5C 43 6F 6D 70 72 65 73 73 65 64 5C 4D }
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
        pe.entry_point == 0x32B0E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0003490E and//Optional Header's EP 
        uint32(0xB0) == 0x00036000 and//Optional Header's Base of Data
        pe.timestamp == 0x51C14D38 and
        pe.data_directories[1].virtual_address == 0x348C0 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x36000 and pe.data_directories[2].size == 0x1F8EA and
        pe.data_directories[5].virtual_address == 0x56000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x34924 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.88 and math.entropy(0, filesize) <= 5.98 and
        filesize >= 325 * 1024 and filesize <= 335 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x52800 and
        8 of ($s*)
}
