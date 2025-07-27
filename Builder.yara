rule AK47_RAT
{
    meta:
        description = "Detects AK47_RAT malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 7C 7C }
        $s1 = "$1fa306eb-ea8c-4b50-a04e-cb79b488be0b"
        $s2 = "wwwwwwwDDDDDDDGO"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s5 = "ThreadSafeObjectProvider`1"
        $s6 = "AssemblyTrademarkAttribute"
        $s7 = "m_MyWebServicesObjectProvider"
        $s8 = "TMATKFRFWMMWHTUKMOOP"
        $s9 = "STAThreadAttribute"
        $s10 = "wwwwwwwwwwwwwwp"
    condition:
        pe.is_pe and
        pe.entry_point == 0x3DBE and 
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x000059BE and//Optional Header's EP 
        pe.timestamp == 0x52C7DBFA and
        pe.data_directories[6].virtual_address == 0x6000 and pe.data_directories[6].size == 0x1C and
        pe.data_directories[5].virtual_address == 0xA000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[2].virtual_address == 0x8000 and pe.data_directories[2].size == 0xAB8 and
        pe.data_directories[1].virtual_address == 0x5964 and pe.data_directories[1].size == 0x57 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.0 and math.entropy(0, filesize) <= 5.2 and
        filesize >= 18 * 1024 and filesize <= 21 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        7 of ($s*)
}