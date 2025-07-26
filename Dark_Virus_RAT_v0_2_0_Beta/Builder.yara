rule Dark_Virus_RAT_v0_2_0_Beta
{
    meta:
        description = "Detects Dark_Virus_RAT_v0_2_0_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "$4f44af02-8ca7-47bb-aff9-bb83508fab05"
        $s3 = "Microsoft.VisualBasic.CompilerServices"
        $s4 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s5 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s6 = "AssemblyTrademarkAttribute" 
        $s7 = "Stub.My.Resources" 
        $s8 = "AssemblyFileVersionAttribute"
        $s9 = "DebuggerStepThroughAttribute" 
        $s10 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase 
    condition:
        pe.is_pe and
        pe.entry_point == 0x1432E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00015F2E and//Optional Header's EP 
        uint32(0xB0) == 0x00016000 and//Optional Header's Base of Data
        pe.timestamp == 0x5301C997 and
        pe.data_directories[1].virtual_address == 0x15ED4 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x18000 and pe.data_directories[2].size == 0x248 and
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x16000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.72 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 80 * 1024 and filesize <= 85 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x14C00 and
        9 of ($s*)
}
