rule A7m3d_Rat_v_0_1_Beta
{
    meta:
        description = "Detects A7m3d_Rat_v_0_1_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 69 5C C0 53 00 00 00 00 02 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
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
        pe.entry_point == 0x1179E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001339E and//Optional Header's EP 
        pe.timestamp == 0x53C05C69 and
        pe.data_directories[6].virtual_address == 0x14000 and pe.data_directories[6].size == 0x1C and
        pe.data_directories[1].virtual_address == 0x13350 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x16000 and pe.data_directories[2].size >= 0x3780 and pe.data_directories[2].size <= 0x37A0 and
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.7 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 84 * 1024 and filesize <= 86 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
