rule Mq5_plus
{
    meta:
        description = "Detects Mq5_plus malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "26-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s2 = "Microsoft.VisualBasic.ApplicationServices"
        $s3 = "Microsoft.VisualBasic.CompilerServices"
        $s4 = "System.Runtime.CompilerServices"
        $s5 = "CompilationRelaxationsAttribute"
        $s7 = "GZipStream"
        $s8 = "v2.0.50727" 
        $s9 = "StandardModuleAttribute" 
        $s10 = "DebuggerHiddenAttribute" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x15FE and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x000033FE and //Optional Header's EP 
        uint32(0xB0) == 0x00004000 and//Optional Header's Base of Data
        // there are no specified date
        pe.data_directories[1].virtual_address == 0x33B0 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x4000 and pe.data_directories[2].size >= 0x4E00 and pe.data_directories[2].size <= 0x4E20 and
        pe.data_directories[5].virtual_address == 0xA000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[9].virtual_address == 0x0 and pe.data_directories[9].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 7.2 and math.entropy(0, filesize) <= 7.3 and
        filesize >= 25 * 1024 and filesize <= 30 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}