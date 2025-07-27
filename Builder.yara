rule BHF_Rat_v0_2_Beta
{
    meta:
        description = "Detects BHF_Rat_v0_2_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "$29c41831-494d-4bcf-93ea-14ce03a5553c"
        $s4 = "UnmanagedFunctionPointerAttribute"
        $s5 = "SetCompatibleTextRenderingDefault"
        $s6 = "lpdwFirstCacheEntryInfoBufferSize"
        $s7 = "Microsoft.VisualBasic.MyServices"
        $s8 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase
        $s9 = "AccessedThroughPropertyAttribute"
        $s10 = "System.Runtime.CompilerServices"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2089E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002249E and//Optional Header's EP 
        uint32(0xB0) == 0x00024000 and//Optional Header's Base of Data
        pe.timestamp == 0x54F58A46 and
        pe.data_directories[1].virtual_address == 0x22444 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x26000 and pe.data_directories[2].size == 0x2E78 and
        pe.data_directories[5].virtual_address == 0x2A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x24000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.65 and math.entropy(0, filesize) <= 5.75 and
        filesize >= 140 * 1024 and filesize <= 145 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x23E00 and
        9 of ($s*)
}