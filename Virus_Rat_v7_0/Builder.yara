rule Virus_Rat_v7_0
{
    meta:
        description = "Detects Virus_Rat_v7_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 54 B8 42 00 00 00 00 00 00 00 00 00 28 B8 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "C:\\Users\\Mr.Mobark\\Desktop\\Stub\\Client\\obj\\Release\\Stub.pdb"
        $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s4 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s5 = "Microsoft.VisualBasic.ApplicationServices"
        $s6 = "Microsoft.VisualBasic.CompilerServices" 
        $s7 = "$5a542c1b-2d36-4c31-b039-26a88d3967da" 
        $s8 = "UnmanagedFunctionPointerAttribute"
        $s9 = "SetCompatibleTextRenderingDefault" 
        $s10 = "lpdwFirstCacheEntryInfoBufferSize"
    condition:
        pe.is_pe and
        pe.entry_point == 0x29A46 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002B846 and//Optional Header's EP 
        uint32(0xB0) == 0x0002C000 and//Optional Header's Base of Data
        pe.timestamp == 0x51526713 and
        pe.data_directories[1].virtual_address == 0x2B7F8 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x401E and
        pe.data_directories[5].virtual_address == 0x32000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.91 and math.entropy(0, filesize) <= 6.01 and
        filesize >= 179 * 1024 and filesize <= 189 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2E000 and
        8 of ($s*)
}
