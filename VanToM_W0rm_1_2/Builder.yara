rule VanToM_W0rm_1_2
{
    meta:
        description = "Detects VanToM_W0rm_1_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "Microsoft.VisualBasic.CompilerServices"
        $s6 = "$7da4050a-ea26-46df-98a2-1ac25749dd20"
        $s7 = "UnmanagedFunctionPointerAttribute"
        $s8 = "SetCompatibleTextRenderingDefault"
        $s9 = "lpdwFirstCacheEntryInfoBufferSize"
        $s10 = "Microsoft.VisualBasic.MyServices"
    condition:
        pe.is_pe and
        pe.entry_point == 0x15F6E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00017B6E and //Optional Header's EP 
        pe.timestamp == 0x52869B3B and
        pe.data_directories[1].virtual_address == 0x17B20 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x1A000 and pe.data_directories[2].size == 0x3260 and
        pe.data_directories[5].virtual_address == 0x1E000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x18000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.6 and math.entropy(0, filesize) <= 5.7 and
        filesize >= 101 * 1024 and filesize <= 103 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x19800 and
        8 of ($s*)
}
