rule Epsilon_RAT_v1_1
{
    meta:
        description = "Detects Epsilon_RAT_v1_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "$5a542c1b-2d36-4c31-b039-26a88d3967da"
        $s6 = "CRYPTPROTECT_PROMPT_ON_PROTECT" nocase
        $s7 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase
        $s8 = "Stub.Resources.resources"
        $s9 = "DOMAIN_VISIBLE_PASSWORD" nocase
        $s10 = "sqlite3_column_count" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x13FFE and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00015BFE and//Optional Header's EP 
        pe.timestamp == 0x534E0825 and
        pe.data_directories[1].virtual_address == 0x15BB0 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x18000 and pe.data_directories[2].size == 0xA68 and
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x16000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.65 and math.entropy(0, filesize) <= 5.72 and
        filesize >= 83 * 1024 and filesize <= 85 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x15200 and
        9 of ($s*)
}
