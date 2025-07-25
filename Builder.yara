rule THTRat
{
    meta:
        description = "Detects THTRat malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7F 30 D1 54 00 00 00 00 02 00 }
        $Overlay = { 7C 62 61 74 75 7C }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "Microsoft.VisualBasic.ApplicationServices"
        $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s4 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s5 = "$STATIC$FileTimeToDate$201112D10112C$lst"
        $s6 = "$STATIC$FileTimeToDate$201112D10112C$lft" 
        $s7 = "$789C1CBF-31EE-11D0-8C39-00C04FD9126B" 
        $s8 = "$5A6F1EC1-2DB1-11D0-8C39-00C04FD9126B"
        $s9 = "$5A6F1EC0-2DB1-11D0-8C39-00C04FD9126B" 
        $s10 = "$2210264d-e9d7-41fd-ad97-1e52353186dd"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2619E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00027D9E and//Optional Header's EP 
        uint32(0xB0) == 0x00028000 and//Optional Header's Base of Data
        pe.timestamp == 0x54D1307F and
        pe.data_directories[1].virtual_address == 0x27D44 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x2A000 and pe.data_directories[2].size == 0x3B18 and
        pe.data_directories[5].virtual_address == 0x2E000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x28000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.3 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 165 * 1024 and filesize <= 175 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2A200 and
        9 of ($s*)
}