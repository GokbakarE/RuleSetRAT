rule Eagle_RAT_1_2
{
    meta:
        description = "Detects Eagle_RAT_1_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 10 00 00 00 20 00 00 80 18 00 00 00 D4 03 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 01 00 00 00 38 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "Microsoft.VisualBasic.ApplicationServices"
        $s3 = "Microsoft.VisualBasic.CompilerServices"
        $s4 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s5 = "$D8D715A3-6E5E-11D0-B3F0-00AA003761C5"
        $s6 = "$C6E13380-30AC-11d0-A18C-00A0C9118956" 
        $s7 = "$0000010c-0000-0000-C000-000000000046" 
        $s8 = "lpdwFirstCacheEntryInfoBufferSize"
        $s9 = "$56a868b3-0ad4-11ce-b03a-0020af0ba770" 
        $s10 = "$8f537d09-f85e-4414-b23b-502e54c79927" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x211D6 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00022FD6 and//Optional Header's EP 
        pe.timestamp == 0x51DF23C2 and
        pe.data_directories[1].virtual_address == 0x22F8C and pe.data_directories[1].size == 0x4A and
        pe.data_directories[2].virtual_address == 0x24000 and pe.data_directories[2].size == 0x8E4 and
        pe.data_directories[5].virtual_address == 0x26000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.86 and math.entropy(0, filesize) <= 5.88 and
        filesize >= 134 * 1024 and filesize <= 137 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x21E00 and
        9 of ($s*)
}
