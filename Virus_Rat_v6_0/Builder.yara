rule Virus_Rat_v6_0
{
    meta:
        description = "Detects Virus_Rat_v6_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 D0 A5 42 00 00 00 00 00 00 00 00 00 A4 A5 02 00 00 00 00 00 00 00 00 00 87 6C 48 51 00 00 00 00 02 00 00 00 3D 00 00 00 F4 A5 02 00 F4 87 02 00 52 53 44 53 6A 25 9B 36 70 87 AC 4B B0 69 19 38 53 EF 0A 3D 01 00 00 00 43 3A 5C 55 73 65 72 73 5C 4D 72 2E 4D 6F 62 61 72 6B 5C 44 65 73 6B 74 6F 70 5C 53 74 75 62 31 2E 70 64 62 00 00 }
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
        pe.entry_point == 0x287C2 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002A5C2 and//Optional Header's EP 
        uint32(0xB0) == 0x0002C000 and//Optional Header's Base of Data
        pe.timestamp == 0x51486C87 and
        pe.data_directories[1].virtual_address == 0x2A574 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x401E and
        pe.data_directories[5].virtual_address == 0x32000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x2A5D8 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.95 and math.entropy(0, filesize) <= 6.05 and
        filesize >= 174 * 1024 and filesize <= 184 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2CE00 and
        8 of ($s*)
}
