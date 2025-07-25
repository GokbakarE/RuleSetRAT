rule Wormins_RAT_0_8
{
    meta:
        description = "Detects Wormins_RAT_0_8 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "MIT License"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "updaterstartuputility.Formulario.resources"
        $s5 = ").NETFramework,Version=v4.0,Profile=Client"
        $s6 = "updaterstartuputility.Resources.resources" 
        $s7 = "Microsoft.VisualBasic.ApplicationServices" 
        $s8 = "DataGridViewColumnHeadersHeightSizeMode"
        $s9 = "Microsoft.VisualBasic.CompilerServices" 
        $s10 = "$32504e9e-c949-4c5f-8108-e84d800222a1"
    condition:
        pe.is_pe and
        pe.entry_point == 0x33A1E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0003561E and//Optional Header's EP 
        uint32(0xB0) == 0x00036000 and//Optional Header's Base of Data
        pe.timestamp == 0x554FD664 and
        pe.data_directories[1].virtual_address == 0x355C8 and pe.data_directories[1].size == 0x53 and
        pe.data_directories[2].virtual_address == 0x38000 and pe.data_directories[2].size == 0x1198 and
        pe.data_directories[5].virtual_address == 0x3A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x36000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 7.0 and math.entropy(0, filesize) <= 7.2 and
        filesize >= 207 * 1024 and filesize <= 217 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x35200 and
        8 of ($s*)
}