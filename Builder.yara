rule SlickRAT_v2_0_Beta
{
    meta:
        description = "Detects SlickRAT_v2_0_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 1C 2C 41 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 D4 03 00 00 7B 7A 7D 02 DF E1 5A BA B5 DB CB 81 60 0A DC BC D6 0A BC 4D AC C5 7C 70 57 19 E6 2A 7A 8B B0 C4 EF FF EB 16 E9 B3 F4 13 CF 7C B9 9C 1D A3 6D BC DF 28 D6 F0 33 A8 2C 68 52 D7 DE 92 49 9B 0B 77 BB A6 E2 85 2E 93 4D 71 AF 3F 1A 5C }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "Microsoft.VisualBasic.ApplicationServices"
        $s3 = "System.Runtime.InteropServices.ComTypes"
        $s4 = "Microsoft.VisualBasic.CompilerServices"
        $s5 = "{b6a8bf30-44d3-4196-b748-b495b2e4325b}"
        $s6 = "{b0c5f3fc-9cc0-451d-bd1a-05a83f3008c5}" 
        $s7 = "$e707dcde-d1cd-11d2-bab9-00c04f8eceae" 
        $s8 = "$CD193BC0-B4BC-11d2-9833-00C04FC31D2E"
        $s9 = "$879a9a66-34d7-440f-be81-47b685864873" 
        $s10 = "$7c23ff90-33af-11d3-95da-00a024a85b51"
    condition:
        pe.is_pe and
        pe.entry_point == 0xF22C and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00012C2C and//Optional Header's EP 
        uint32(0xB0) == 0x00002000 and//Optional Header's Base of Data
        pe.timestamp == 0x4D66F035 and
        pe.data_directories[1].virtual_address == 0x12BF4 and pe.data_directories[1].size == 0x58 and
        pe.data_directories[2].virtual_address == 0x2000 and pe.data_directories[2].size >= 0x300 and pe.data_directories[2].size <= 0x3FF and
        pe.data_directories[5].virtual_address == 0x20000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[12].virtual_address == 0x12C1C and pe.data_directories[12].size == 0x8 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.93 and math.entropy(0, filesize) <= 6.03 and
        filesize >= 104 * 1024 and filesize <= 114 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}