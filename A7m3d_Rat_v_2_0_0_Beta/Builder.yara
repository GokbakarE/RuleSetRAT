rule A7m3d_Rat_v_2_0_0_Beta
{
    meta:
        description = "Detects A7m3d_Rat_v_2_0_0_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B1 49 C4 53 00 00 00 00 02 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "Create__Instance__"
        $s3 = "$8c0a0be4-c2d9-43fd-8362-d331a08ed069"
        $s4 = "lpdwFirstCacheEntryInfoBufferSize"
        $s5 = "CRYPTPROTECT_PROMPT_ON_PROTECT"
        $s6 = "Microsoft.VisualBasic.CompilerServices"
        $s7 = "DebuggerStepThroughAttribute"
        $s8 = "MAX_CACHE_ENTRY_INFO_SIZE"
        $s9 = "MD5CryptoServiceProvider"
        $s10 = "DOMAIN_VISIBLE_PASSWORD"
    condition:
        pe.is_pe and
        pe.entry_point == 0x1039E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00011F9E and//Optional Header's EP 
        pe.timestamp == 0x53C449B1 and
        pe.data_directories[6].virtual_address == 0x12000 and pe.data_directories[6].size == 0x1C and
        pe.data_directories[1].virtual_address == 0x11F48 and pe.data_directories[1].size == 0x53 and
        pe.data_directories[2].virtual_address == 0x14000 and pe.data_directories[2].size >= 0x3600 and pe.data_directories[2].size <= 0x3800 and
        pe.data_directories[5].virtual_address == 0x18000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.7 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 79 * 1024 and filesize <= 81 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
