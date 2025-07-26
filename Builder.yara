rule FD_Rat
{
    meta:
        description = "Detects FD_Rat malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 50 B8 42 00 00 00 00 00 00 00 00 00 24 B8 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s6 = "$D8D715A3-6E5E-11D0-B3F0-00AA003761C5"
        $s7 = "$0000010c-0000-0000-C000-000000000046"
        $s8 = "$00855B90-CE1B-11d0-BD4F-00A0C911CE86"
        $s9 = "$56a86893-0ad4-11ce-b03a-0020af0ba770"
        $s10 = "$56a86895-0ad4-11ce-b03a-0020af0ba770"
    condition:
        pe.is_pe and
        pe.entry_point == 0x29A42 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002B842 and//Optional Header's EP 
        pe.timestamp == 0x51543BA3 and
        pe.data_directories[1].virtual_address == 0x2B7F4 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x401E and
        pe.data_directories[5].virtual_address == 0x32000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.9 and math.entropy(0, filesize) <= 6.0 and
        filesize >= 183 * 1024 and filesize <= 185 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2E000 and
        8 of ($s*)
}