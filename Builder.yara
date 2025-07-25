rule Virus_Rat_v4_0
{
    meta:
        description = "Detects Virus_Rat_v4_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C8 F3 3D 51 00 00 00 00 02 00 00 00 54 00 00 00 1C 80 01 00 1C 5A 01 00 52 53 44 53 E2 7A 48 E1 08 83 0E 49 BC 46 B8 D8 14 1D 00 BD 01 00 00 00 43 3A 5C 55 73 65 72 73 5C 4D }
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
        pe.entry_point == 0x159CE and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x000175CE and//Optional Header's EP 
        uint32(0xB0) == 0x00018000 and//Optional Header's Base of Data
        pe.timestamp == 0x513DF3C8 and
        pe.data_directories[1].virtual_address == 0x1757C and pe.data_directories[1].size == 0x4F and
        pe.data_directories[2].virtual_address == 0x1A000 and pe.data_directories[2].size == 0x3FA0 and
        pe.data_directories[5].virtual_address == 0x1E000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x18000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.98 and math.entropy(0, filesize) <= 6.08 and
        filesize >= 98 * 1024 and filesize <= 108 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x19E00 and
        9 of ($s*)
}