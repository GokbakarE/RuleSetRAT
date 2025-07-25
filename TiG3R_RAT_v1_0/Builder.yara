rule TiG3R_RAT_v1_0
{
    meta:
        description = "Detects TiG3R_RAT_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AF F0 6F 52 00 00 00 00 02 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" 
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "Microsoft.VisualBasic.CompilerServices"
        $s6 = "$8c0a0be4-c2d9-43fd-8362-d331a08ed069" 
        $s7 = "UnmanagedFunctionPointerAttribute" 
        $s8 = "SetCompatibleTextRenderingDefault"
        $s9 = "Microsoft.VisualBasic.MyServices" 
        $s10 = "lpdwFirstCacheEntryInfoBufferSize"
    condition:
        pe.is_pe and
        pe.entry_point == 0x13D9E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001599E and//Optional Header's EP 
        uint32(0xB0) == 0x00016000 and//Optional Header's Base of Data
        pe.timestamp == 0x526FF0AF and
        pe.data_directories[1].virtual_address == 0x1594C and pe.data_directories[1].size == 0x4F and
        pe.data_directories[2].virtual_address == 0x18000 and pe.data_directories[2].size == 0xA28 and 
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x16000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.69 and math.entropy(0, filesize) <= 5.79 and
        filesize >= 78 * 1024 and filesize <= 88 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x14E00 and
        9 of ($s*)
}
