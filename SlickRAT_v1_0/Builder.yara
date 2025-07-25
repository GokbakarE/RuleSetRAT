rule SlickRAT_v1_0
{
    meta:
        description = "Detects SlickRAT_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "System.Runtime.InteropServices.ComTypes"
        $s6 = "Microsoft.VisualBasic.CompilerServices" 
        $s7 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase 
        $s8 = "AccessedThroughPropertyAttribute"
        $s9 = "CompilationRelaxationsAttribute" 
        $s10 = "Me_Timer_Passed"
    condition:
        pe.is_pe and
        pe.entry_point == 0xEA2E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001062E and//Optional Header's EP 
        uint32(0xB0) == 0x00012000 and//Optional Header's Base of Data
        pe.timestamp == 0x4D594AA1 and
        pe.data_directories[1].virtual_address == 0x105E0 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x14000 and pe.data_directories[2].size >= 0x23A0 and pe.data_directories[2].size <= 0x23FF and
        pe.data_directories[5].virtual_address == 0x18000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x12000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.84 and math.entropy(0, filesize) <= 5.94 and
        filesize >= 64 * 1024 and filesize <= 74 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
