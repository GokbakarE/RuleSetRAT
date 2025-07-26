rule Dark_Connect_v3_4
{
    meta:
        description = "Detects Dark_Connect_v3_4 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "26-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "Microsoft.VisualBasic.CompilerServices"
        $s6 = "$51e50cb0-04cb-4b2a-b1e3-3f94e716985f"
        $s7 = "PAPADDINGX" nocase
        $s8 = "v2.0.50727" 
        $s9 = "</assembly>" 
        $s10 = "System.ComponentModel.Design" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x2E4E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00004A4E and //Optional Header's EP 
        uint32(0xB0) == 0x00006000 and//Optional Header's Base of Data
        pe.timestamp == 0x55BA6B5F and
        pe.data_directories[1].virtual_address == 0x49F4 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x8000 and pe.data_directories[2].size == 0xE9F8 and 
        pe.data_directories[5].virtual_address == 0x18000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x6000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 7.72 and math.entropy(0, filesize) <= 7.82 and
        filesize >= 70 * 1024 and filesize <= 73 * 1024 and
        pe.overlay.size == 0 and 
        9 of ($s*)
}
