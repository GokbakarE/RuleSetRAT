rule UGSec_RAT
{
    meta:
        description = "Detects UGSec_RAT malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s3 = "Client.Properties.Resources.resources"
        $s4 = "$b9ce8a6c-73f1-4a00-9e9b-018f0f807ea7"
        $s5 = "UnmanagedFunctionPointerAttribute"
        $s6 = "SetCompatibleTextRenderingDefault"
        $s7 = "Microsoft.VisualBasic.MyServices"
        $s8 = "System.Runtime.CompilerServices"
        $s9 = "CompilationRelaxationsAttribute"
        $s10 = "AssemblyFileVersionAttribute"
    condition:
        pe.is_pe and
        pe.entry_point >= 0x71A0 and pe.entry_point <= 0x71C0 and
        $EP at (pe.entry_point) and
        uint32(0xA8) >= 0x00008FA0 and uint32(0xA8) <= 0x00008FC0 and//Optional Header's EP 
        // there are no specified date
        pe.data_directories[6].virtual_address == 0x4044 and pe.data_directories[6].size == 0x1C and
        pe.data_directories[2].virtual_address == 0xC000 and pe.data_directories[2].size == 0x5AC and
        pe.data_directories[1].virtual_address >= 0x8F50 and pe.data_directories[1].virtual_address <= 0x8F70 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[5].virtual_address == 0xA000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.7 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 29 * 1024 and filesize <= 32 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}