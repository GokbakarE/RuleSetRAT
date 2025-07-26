rule Fighter_RAT_v1_0
{
    meta:
        description = "Detects Fighter_RAT_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s3 = "0ZWQzNDFkNGEtMzM3MC00NDlhLTkyYzAtNTNkNzRlMDRjOGFj"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "{df6bde35-3434-4c5c-8ab7-993e5d6679b2}"
        $s6 = "$29c41831-494d-4bcf-93ea-14ce03a5553c"
        $s7 = "SetCompatibleTextRenderingDefault"
        $s8 = "TripleDESCryptoServiceProvider"
        $s9 = "System.Text.RegularExpressions"
        $s10 = "get_UseCompatibleTextRendering"
    condition:
        pe.is_pe and
        pe.entry_point == 0x54EC3 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00056CC3 and//Optional Header's EP 
        pe.timestamp == 0x5362F69A and
        pe.data_directories[1].virtual_address == 0x56C79 and pe.data_directories[1].size == 0x4A and
        pe.data_directories[2].virtual_address == 0x58000 and pe.data_directories[2].size == 0x2B6A and
        pe.data_directories[5].virtual_address == 0x5C000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.7 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 350 * 1024 and filesize <= 352 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x57E00 and
        8 of ($s*)
}
