rule CobianRAT_v1_0_40_7
{
    meta:
        description = "Detects CobianRAT_v1_0_40_7 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "System.Runtime.Serialization.Formatters.Binary"
        $s5 = "$ab670678-0cae-4d28-9df7-df30c6109483"
        $s6 = "Dispose__Instance__"
        $s7 = "ComVisibleAttribute"
        $s8 = "Create__Instance__"
        $s9 = "DDDDDDDDDDDDDDp"
        $s10 = "B.My.Resources"
    condition:
        pe.is_pe and
        pe.entry_point >= 0x6A40 and pe.entry_point <= 0x6AC0 and
        $EP at (pe.entry_point) and
        uint32(0xA8) >= 0x00008840 and uint32(0xA8) <= 0x000088B0 and //Optional Header's EP 
        uint32(0xB0) == 0x00000000 and//Optional Header's Base of Data
         //no specific date //
        pe.data_directories[1].virtual_address >= 0x8800 and pe.data_directories[1].virtual_address <= 0x88FF and
        pe.data_directories[1].size >= 0x40 and pe.data_directories[1].size <= 0x60 and
        pe.data_directories[2].virtual_address == 0xA000 and pe.data_directories[2].size == 0xA00 and
        pe.data_directories[5].virtual_address == 0xC000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.45 and math.entropy(0, filesize) <= 5.55 and
        filesize >= 25 * 1024 and filesize <= 35 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}