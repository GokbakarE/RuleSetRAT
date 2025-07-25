rule wiRAT
{
    meta:
        description = "Detects wiRAT malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "MIT License"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 71 77 65 72 74 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" 
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "Microsoft.VisualBasic.CompilerServices"
        $s6 = "$STATIC$GetRandom$202888$Generator$Init" 
        $s7 = "set_CheckForIllegalCrossThreadCalls" 
        $s8 = "$da06ac9c-ad06-4559-b6b4-0cd4c771e49f"
        $s9 = "TripleDESCryptoServiceProvider" 
        $s10 = "Wi_Rat.Resources.resources" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x17D4E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001994E and//Optional Header's EP 
        uint32(0xB0) == 0x0001A000 and//Optional Header's Base of Data
        pe.timestamp == 0x534EA4d5 and
        pe.data_directories[1].virtual_address == 0x198F8 and pe.data_directories[1].size == 0x53 and
        pe.data_directories[2].virtual_address == 0x1C000 and pe.data_directories[2].size == 0x3B60 and 
        pe.data_directories[5].virtual_address == 0x20000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x1A000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.67 and math.entropy(0, filesize) <= 5.77 and
        filesize >= 106 * 1024 and filesize <= 116 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x1BE00 and
        9 of ($s*)
}