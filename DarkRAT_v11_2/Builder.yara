rule DarkRAT_v11_2
{
    meta:
        description = "Detects DarkRAT_v11_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 CC 1F 43 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 34 5F 03 00 7B 7A 7D 02 9F B3 1E B3 A1 A7 BF 92 81 17 1E D0 86 28 3F 6B 30 03 5E 5D 39 E9 F1 63 FA 00 A1 91 D6 C5 DE F3 D2 9E 1C 20 F9 8F 8E 8F 85 A6 74 84 C8 D6 CA 55 0E 33 6C 1F 23 78 54 EA 67 B5 03 51 40 1F 90 50 80 42 A1 8D 29 71 72 0A EF 49 4D 1B B4 FF 83 E3 2A 6A E6 8C 92 2C 9F FD }
        $Overlay = { 40 31 39 30 36 64 61 72 6B 31 39 39 36 63 6F 64 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "Microsoft.VisualBasic.ApplicationServices"
        $s3 = "Microsoft.VisualBasic.CompilerServices"
        $s4 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s5 = "{88398440-486f-46d0-bb45-521b8ee8871e}"
        $s6 = "{175dbf86-ae47-4343-a942-6b699ed60f82}" 
        $s7 = "$fd8e4b0b-919a-467e-8f8d-58a2c41e6c4b" 
        $s8 = "$7c23ff90-33af-11d3-95da-00a024a85b51"
        $s9 = "set_UseCompatibleStateImageBehavior" 
        $s10 = "GetManifestResourceStream"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2EFDC and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00031FDC and//Optional Header's EP 
        uint32(0xB0) == 0x00002000 and//Optional Header's Base of Data
        pe.timestamp == 0x4D62DABD and
        pe.data_directories[1].virtual_address == 0x31FA4 and pe.data_directories[1].size == 0x58 and
        pe.data_directories[2].virtual_address == 0x2000 and pe.data_directories[2].size == 0x20C60 and
        pe.data_directories[5].virtual_address == 0x78000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[12].virtual_address == 0x31FCC and pe.data_directories[12].size == 0x8 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 7.42 and math.entropy(0, filesize) <= 7.5 and
        filesize >= 455 * 1024 and filesize <= 465 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x73600 and
        9 of ($s*)
}
