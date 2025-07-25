rule Snake_Worm_v0_1
{
    meta:
        description = "Detects Snake_Worm_v0_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXP" nocase
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "\\njRDP\\Client\\Client\\obj\\Debug\\Stub.pdb"
        $s6 = "$5a542c1b-2d36-4c31-b039-26a88d3967da"
        $s7 = "AccessedThroughPropertyAttribute"
        $s8 = "AsyncCallback" 
        $s9 = "CompilationRelaxationsAttribute"
        $s10 = "m_MyWebServicesObjectProvider"
    condition:
        pe.is_pe and
        pe.entry_point == 0x67FE and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x000083FE and//Optional Header's EP 
        uint32(0xB0) == 0x0000A000 and//Optional Header's Base of Data
        pe.timestamp == 0x5206E525 and
        pe.data_directories[1].virtual_address == 0x83A4 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0xC000 and pe.data_directories[2].size == 0x614 and
        pe.data_directories[5].virtual_address == 0xE000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0xA000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.43 and math.entropy(0, filesize) <= 5.53 and
        filesize >= 24 * 1024 and filesize <= 34 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x7600 and
        9 of ($s*)
}
