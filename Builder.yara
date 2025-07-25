rule Kurd_Rat_v1_0_Beta_Online
{
    meta:
        description = "Detects Kurd_Rat_v1_0_Beta_Online malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 50 B8 42 00 00 00 00 00 00 00 00 00 24 B8 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXP" nocase
        $s3 = "Microsoft.VisualBasic.CompilerServices"
        $s4 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s5 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s6 = "$93E5A4E0-2D50-11d2-ABFA-00A0C9C6E38D" 
        $s7 = "$8f537d09-f85e-4414-b23b-502e54c79927" 
        $s8 = "$6B652FFF-11FE-4fce-92AD-0266B5D7C78F"
        $s9 = "$5a804648-4f66-4867-9c43-4f5c822cf1b8" 
        $s10 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase 
    condition:
        pe.is_pe and
        pe.entry_point == 0x29A42 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002B842 and//Optional Header's EP 
        uint32(0xB0) == 0x0002C000 and//Optional Header's Base of Data
        pe.timestamp == 0x51543BA3 and
        pe.data_directories[1].virtual_address == 0x2B7F4 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x4020 and
        pe.data_directories[5].virtual_address == 0x32000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.95 and math.entropy(0, filesize) <= 6.0 and
        filesize >= 182 * 1024 and filesize <= 187 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2E000 and
        9 of ($s*)
}