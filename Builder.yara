rule Almjhool_1_1
{
    meta:
        description = "Detects Almjhool_1_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 50 B8 42 00 00 00 00 00 00 00 00 00 24 B8 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s3 = "$B196B28B-BAB4-101A-B69C-00AA00341D07"
        $s4 = "$8f537d09-f85e-4414-b23b-502e54c79927"
        $s5 = "ROTFLAGS_REGISTRATIONKEEPSALIVE"
        $s6 = "TripleDESCryptoServiceProvider"
        $s7 = "CRYPTPROTECT_PROMPT_ON_PROTECT"
        $s8 = "MAX_CACHE_ENTRY_INFO_SIZE"
        $s9 = "sqlite3_column_table_name"
        $s10 = "ISampleGrabberCB_BufferCB"
    condition:
        pe.is_pe and
        pe.entry_point == 0x29A42 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002B842 and//Optional Header's EP 
        pe.timestamp == 0x51543BA3 and
        pe.data_directories[1].virtual_address == 0x2B7F4 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x401E and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.9 and math.entropy(0, filesize) <= 6.0 and
        filesize >= 183 * 1024 and filesize <= 185 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2E000 and
        8 of ($s*)
}