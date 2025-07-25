rule santi_RAT
{
    meta:
        description = "Detects santi_RAT malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 51 2D 4C 63 38 52 4B 79 62 24 2D 55 29 37 66 66 39 71 66 74 38 46 4E 48 4A 4E 62 54 6E 74 38 47 28 34 4B 5A 43 32 70 39 42 32 3D 46 50 46 37 70 28 56 4D 23 53 25 79 5F 53 40 44 78 5A 34 23 61 20 65 68 4E 47 75 36 36 78 24 4C 37 2D 40 40 35 7A 37 55 24 74 4E 59 71 44 64 45 72 51 6B 6A 21 72 51 24 61 29 5E 4D 77 45 50 21 4B 4D 4D 45 32 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s3 = "{f265468a-63c9-4cb6-b919-45a987d6111a}"
        $s4 = "{daf59653-c521-4568-b527-84306814408b}"
        $s5 = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        $s6 = "$ac045e25-5d9e-42b8-a1ce-4c3a95960eae"
        $s7 = "ZZZZZZZZZZZZZR%ZZZZZZZZZZZZZZZZZZZZ"
        $s8 = "System.Runtime.CompilerServices"
        $s9 = "E>>%C:?5?7;A<25H;11I<44@>9>-@@@"
        $s10 = "CompilationRelaxationsAttribute"
    condition:
        pe.is_pe and
        pe.entry_point == 0x1C0AA and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001DEAA and//Optional Header's EP 
        pe.timestamp == 0x519D747B and
        pe.data_directories[1].virtual_address == 0x1DE60 and pe.data_directories[1].size == 0x4A and
        pe.data_directories[2].virtual_address == 0x1E000 and pe.data_directories[2].size == 0x6186 and
        pe.data_directories[5].virtual_address == 0x26000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 6.89 and math.entropy(0, filesize) <= 6.95 and
        filesize >= 143 * 1024 and filesize <= 145 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x22600 and
        9 of ($s*)
}