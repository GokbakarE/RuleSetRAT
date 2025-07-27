import "pe"
import "math"
rule A_311_Death_v1_02
{
    meta: //Description...
        description = "Detects A_311_Death_v1_02 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings: //$EP refers to Entry Point
        $EP = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 }
        $s1 = "rz-{9#.r6"
        $s2 = "<t>u6v.0w&O"
        $s3 = "GetProcAddress"
        $s4 = "LoadLibraryA" // Top 10 longest strings from builded malwares
        $s5 = "KERNEL32.dll"
        $s6 = "Ngh:yi2j0"
        $s7 = "DEFGHIJK"
        $s8 = ";kr|{.}x"
        $s9 = "proggam"
        $s10 = "EF*GTTH"
    condition:
        pe.is_pe and
        pe.entry_point == 0x58CB and
        $EP at (pe.entry_point) and // $EP checks for Entry Point
        uint32(0x34) == 0x000126CB and//Optional Header's EP 
        pe.timestamp == 0x21584450 and // date 
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.data_directories[1].virtual_address == 0x12790 and pe.data_directories[1].size == 0x34 and
        pe.data_directories[2].virtual_address == 0xD000 and pe.data_directories[2].size == 0x3A0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        math.entropy(0, filesize) >= 7.6 and math.entropy(0, filesize) <= 7.7 and
        filesize >= 21 * 1024 and filesize <= 24 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        8 of ($s*)
}
rule A_311_Death_v0_99_8
{
    meta:
        description = "Detects A_311_Death_v0_99_8 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 }
        $s1 = "Di,;ctcXwCu"
        $s2 = "KERN`L32.D"
        $s3 = "GetProcAddress"
        $s4 = "LoadLibraryA"
        $s5 = "KERNEL32.dll"
        $s6 = "IetV0rsio"
        $s7 = "I0E_yPoki"
        $s8 = "dl<>}}RTW"
        $s9 = "X3LAE&b<"
        $s10 = "PriouMs"
    condition:
        pe.is_pe and
        pe.entry_point == 0x55E1 and
        $EP at (pe.entry_point) and
        uint32(0x34) == 0x000123E1 and//Optional Header's EP 
        pe.timestamp == 0x21475346 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.data_directories[1].virtual_address == 0x124A6 and pe.data_directories[1].size == 0x34 and
        pe.data_directories[2].virtual_address == 0xD000 and pe.data_directories[2].size == 0x3A0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        math.entropy(0, filesize) >= 7.4 and math.entropy(0, filesize) <= 7.6 and
        filesize >= 21 * 1024 and filesize <= 24 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        8 of ($s*)
}
rule A_311_Death_v1_00_A
{
    meta:
        description = "Detects A_311_Death_v1_00_A malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 }
        $s1 = "56789+/_7U"
        $s2 = "<t>u6v.w`&O"
        $s3 = "GetProcAddress"
        $s4 = "LoadLibraryA"
        $s5 = "KERNEL32.dll"
        $s6 = "x8pVr:Pv"
        $s7 = "OFTWA6RE"
        $s8 = "KLMNpQRS"
        $s9 = "aT!nNPmw"
        $s10 = "=>+Y=#n"
    condition:
        pe.is_pe and
        pe.entry_point == 0x57B3 and
        $EP at (pe.entry_point) and
        uint32(0x34) == 0x000125B3 and//Optional Header's EP 
        pe.timestamp == 0x21584450 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.data_directories[1].virtual_address == 0x12678 and pe.data_directories[1].size == 0x34 and
        pe.data_directories[2].virtual_address == 0xD000 and pe.data_directories[2].size == 0x3A0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        math.entropy(0, filesize) >= 7.6 and math.entropy(0, filesize) <= 7.7 and
        filesize >= 21 * 1024 and filesize <= 24 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        8 of ($s*)
}
rule Acropolis_1_0 
{
    meta:
        description = "Detects Acropolis_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "24-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F4 B8 40 C4 44 00 E8 24 9A FB FF }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
        $s2 = "=$=(=0=4=<=@=H=L=T=X=`=d=l=p=x=|="
        $s3 = "Software\\Borland\\Delphi\\Locales"
        $s4 = ">>?B?F?J?N?R?V?Z?^?b?f?j?n?r?v?"
        $s5 = "2#3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
        $s6 = ";*;/;:;?;D;O;T;Y;d;i;n;y;~;"
        $s7 = "Root=$DefaultWinport.com"
        $s8 = "=&=+=9=B=G=L=Z=c=h=m={="
        $s9 = "4<4D4H4L4P4T4X4\\4`4d4x4"
        $s10 = "0#000B0J0R0Z0b0j0r0z0"
    condition:
        pe.is_pe and
        pe.entry_point == 0x4B9A8 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0004C5A8 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x52000 and pe.data_directories[1].size == 0x1E90 and
        pe.data_directories[2].virtual_address == 0x5B000 and pe.data_directories[2].size == 0x5F200 and 
        pe.data_directories[5].virtual_address == 0x56000 and pe.data_directories[5].size == 0x4940 and
        pe.imports("gdi32.dll", "SetWindowOrgEx") and
        math.entropy(0, filesize) >= 7.5 and math.entropy(0, filesize) <= 7.6 and
        filesize >= 715 * 1024 and filesize <= 717 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        7 of ($s*)
}
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
rule Almjhool_1_1
{
    meta:
        description = "Detects Almjhool_1_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 50 B8 42 00 00 00 00 00 00 00 00 00 24 B8 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s3 = "$B196B28B-BAB4-101A-B69C-00AA00341D07"
        $s4 = "$8f537d09-f85e-4414-b23b-502e54c79927"
        $s5 = "ROTFLAGS_REGISTRATIONKEEPSALIVE"
        $s6 = "TripleDESCryptoServiceProvider"
        $s7 = "CRYPTPROTECT_PROMPT_ON_PROTECT"
        $s8 = "MAX_CACHE_ENTRY_INFO_SIZE"
        $s9 = "sqlite3_column_table_name"
        $s10 = "ISampleGrabberCB_BufferCB"
    condition:
        pe.is_pe and
        pe.entry_point == 0x29A42 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002B842 and//Optional Header's EP 
        pe.timestamp == 0x51543BA3 and
        pe.data_directories[1].virtual_address == 0x2B7F4 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x401E and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.9 and math.entropy(0, filesize) <= 6.0 and
        filesize >= 183 * 1024 and filesize <= 185 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2E000 and
        8 of ($s*)
}
rule A7m3d_Rat_v_0_1_Beta
{
    meta:
        description = "Detects A7m3d_Rat_v_0_1_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 69 5C C0 53 00 00 00 00 02 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s3 = "$8c0a0be4-c2d9-43fd-8362-d331a08ed069"
        $s4 = "lpdwFirstCacheEntryInfoBufferSize"
        $s5 = "CRYPTPROTECT_PROMPT_ON_PROTECT"
        $s6 = "Microsoft.VisualBasic.CompilerServices"
        $s7 = "DebuggerStepThroughAttribute"
        $s8 = "MAX_CACHE_ENTRY_INFO_SIZE"
        $s9 = "MD5CryptoServiceProvider"
        $s10 = "DOMAIN_VISIBLE_PASSWORD"
    condition:
        pe.is_pe and
        pe.entry_point == 0x1179E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001339E and//Optional Header's EP 
        pe.timestamp == 0x53C05C69 and
        pe.data_directories[6].virtual_address == 0x14000 and pe.data_directories[6].size == 0x1C and
        pe.data_directories[1].virtual_address == 0x13350 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x16000 and pe.data_directories[2].size >= 0x3780 and pe.data_directories[2].size <= 0x37A0 and
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.7 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 84 * 1024 and filesize <= 86 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        8 of ($s*)
}
rule A7m3d_Rat_v_2_0_0_Beta
{
    meta:
        description = "Detects A7m3d_Rat_v_2_0_0_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B1 49 C4 53 00 00 00 00 02 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "Create__Instance__"
        $s3 = "$8c0a0be4-c2d9-43fd-8362-d331a08ed069"
        $s4 = "lpdwFirstCacheEntryInfoBufferSize"
        $s5 = "CRYPTPROTECT_PROMPT_ON_PROTECT"
        $s6 = "Microsoft.VisualBasic.CompilerServices"
        $s7 = "DebuggerStepThroughAttribute"
        $s8 = "MAX_CACHE_ENTRY_INFO_SIZE"
        $s9 = "MD5CryptoServiceProvider"
        $s10 = "DOMAIN_VISIBLE_PASSWORD"
    condition:
        pe.is_pe and
        pe.entry_point == 0x1039E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00011F9E and//Optional Header's EP 
        pe.timestamp == 0x53C449B1 and
        pe.data_directories[6].virtual_address == 0x12000 and pe.data_directories[6].size == 0x1C and
        pe.data_directories[1].virtual_address == 0x11F48 and pe.data_directories[1].size == 0x53 and
        pe.data_directories[2].virtual_address == 0x14000 and pe.data_directories[2].size >= 0x3600 and pe.data_directories[2].size <= 0x3800 and
        pe.data_directories[5].virtual_address == 0x18000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.7 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 79 * 1024 and filesize <= 81 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        8 of ($s*)
}
rule Fighter_RAT_v1_0
{
    meta:
        description = "Detects Fighter_RAT_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s3 = "0ZWQzNDFkNGEtMzM3MC00NDlhLTkyYzAtNTNkNzRlMDRjOGFj"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "{df6bde35-3434-4c5c-8ab7-993e5d6679b2}"
        $s6 = "$29c41831-494d-4bcf-93ea-14ce03a5553c"
        $s7 = "SetCompatibleTextRenderingDefault"
        $s8 = "TripleDESCryptoServiceProvider"
        $s9 = "System.Text.RegularExpressions"
        $s10 = "get_UseCompatibleTextRendering"
    condition:
        pe.is_pe and
        pe.entry_point == 0x54EC3 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00056CC3 and//Optional Header's EP 
        pe.timestamp == 0x5362F69A and
        pe.data_directories[1].virtual_address == 0x56C79 and pe.data_directories[1].size == 0x4A and
        pe.data_directories[2].virtual_address == 0x58000 and pe.data_directories[2].size == 0x2B6A and
        pe.data_directories[5].virtual_address == 0x5C000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.7 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 350 * 1024 and filesize <= 352 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x57E00 and
        8 of ($s*)
}
rule FD_Rat
{
    meta:
        description = "Detects FD_Rat malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 50 B8 42 00 00 00 00 00 00 00 00 00 24 B8 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s6 = "$D8D715A3-6E5E-11D0-B3F0-00AA003761C5"
        $s7 = "$0000010c-0000-0000-C000-000000000046"
        $s8 = "$00855B90-CE1B-11d0-BD4F-00A0C911CE86"
        $s9 = "$56a86893-0ad4-11ce-b03a-0020af0ba770"
        $s10 = "$56a86895-0ad4-11ce-b03a-0020af0ba770"
    condition:
        pe.is_pe and
        pe.entry_point == 0x29A42 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002B842 and//Optional Header's EP 
        pe.timestamp == 0x51543BA3 and
        pe.data_directories[1].virtual_address == 0x2B7F4 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x401E and
        pe.data_directories[5].virtual_address == 0x32000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.9 and math.entropy(0, filesize) <= 6.0 and
        filesize >= 183 * 1024 and filesize <= 185 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2E000 and
        8 of ($s*)
}
rule FunFucker_0_8_Alpha
{
    meta:
        description = "Detects FunFucker_0_8_Alpha malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 78 8A 49 00 E8 34 D6 F6 FF 33 C0 55 68 BB 90 49 00 64 FF 30 64 89 20 B2 01 A1 C0 7B 49 00 E8 32 A6 F6 FF A3 D8 0F 4A 00 6A 00 B9 F4 89 49 00 B2 01 A1 04 7F 49 00 E8 2A EF FF FF 6A 01 E8 8F 4E F7 FF A1 D8 0F 4A 00 E8 AD EB FF FF EB ED 33 C0 5A 59 59 64 89 10 68 C2 90 49 00 C3 E9 8C AD F6 FF EB F8 E8 B1 B2 F6 FF 90 }
        $Overlay = { 53 4F 21 23 44 59 4E 44 4E 53 B6 }
        $s1 = "Extended_UNIX_Code_Fixed_Width_for_Japanese"
        $s2 = "C:\\build\\indy10VCL\\Lib\\Core\\IdIOHandler.pas"
        $s3 = "(EIdAlreadyRegisteredAuthenticationMethod"
        $s4 = "C:\\build\\indy10VCL\\Lib\\System\\IdStack.pas"
        $s5 = "%EIdSocksUDPNotSupportedBySOCKSVersion"
        $s6 = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        $s7 = "9(9094989<9@9D9H9L9P9`9y9"
        $s8 = "PC-Multilingual-850+euro"
        $s9 = "C:\\build\\indy10VCL\\Lib\\Protocols\\IdCoder00E.pas"
        $s10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        pe.is_pe and
        pe.entry_point == 0x98458 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00099058 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xA1000 and pe.data_directories[1].size == 0x2634 and
        pe.data_directories[2].virtual_address == 0xB2000 and pe.data_directories[2].size == 0x7600 and
        pe.data_directories[5].virtual_address == 0xA6000 and pe.data_directories[5].size == 0xB344 and
        pe.imports("user32.dll") and
        pe.imports("user32.dll", "BlockInput") and
        pe.imports("WS2_32.DLL") and
        pe.imports("WS2_32.DLL", "ioctlsocket") and
        pe.imports("winmm.dll") and
        pe.imports("winmm.dll", "mciSendStringA") and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.5 and math.entropy(0, filesize) <= 6.6 and
        filesize >= 713 * 1024 and filesize <= 715 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0xB2800 and
        8 of ($s*)
}
rule FeRAT_v1_00
{
    meta:
        description = "Detects FeRAT_v1_00 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F4 B8 20 21 45 00 E8 68 40 FB FF A1 A0 3E 45 00 8B 00 E8 10 10 FF FF 8B 0D 8C 3F 45 00 A1 A0 3E 45 00 8B 00 8B 15 D0 C5 44 00 E8 10 10 FF FF A1 A0 3E 45 00 8B 00 E8 84 10 FF FF E8 C3 15 FB FF 8D 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 0D 0A }
        $s1 = "software\\microsoft\\windows\\currentversion\\electronicCommerce\\UserInfo"
        $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Network\\LanMan\\C"
        $s3 = "50585<5@5D5H5L5P5T5X5\\5`5d5h55696=6A6E6I6M6Q6U6Y6]6a6e6i6"
        $s4 = "http://web.icq.com/whitepages/page_me/1,,,00.html?to="
        $s5 = "\\Hardware\\Description\\System\\CentralProcessor\\0"
        $s6 = "1$1(1,1014181<1@1D1H1L1P1T1X1\\1`1d1h1l1p1t1x1|1"
        $s7 = "System\\CurrentControlSet\\Services\\VxD\\VNETSUP\\"
        $s8 = "&from=ONLINE&fromemail=notify@ayf.com&body="
        $s9 = "7$7(787@7D7H7L7P7T7X7\\7`7d7h7l7p7t7x7|7"
        $s10 = "6(686@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6"
    condition:
        pe.is_pe and
        pe.entry_point == 0x51678 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00052278 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x56000 and pe.data_directories[1].size == 0x253A and
        pe.data_directories[2].virtual_address == 0x61000 and pe.data_directories[2].size == 0x3C00 and
        pe.data_directories[5].virtual_address == 0x5B000 and pe.data_directories[5].size == 0x5708 and
        pe.imports("urlmon.dll") and
        pe.imports("urlmon.dll", "URLDownloadToFileA") and
        pe.imports("netapi32.dll") and
        pe.imports("netapi32.dll", "Netbios") and
        pe.imports("ole32.dll") and
        pe.imports("ole32.dll", "IsEqualGUID") and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.5 and math.entropy(0, filesize) <= 6.6 and
        filesize >= 376 * 1024 and filesize <= 378 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x5E600 and
        8 of ($s*)
}
rule Amitis_1_4_2
{
    meta:
        description = "Detects Amitis_1_4_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 B0 48 00 8D BE 00 60 F7 FF C7 87 10 67 0B 00 99 4C 32 74 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 }
        $s1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s2 = "E0-3AEA-1069-A2D8-08002B30"
        $s3 = "kernel32.dll^GetLongPqNq"
        $s4 = "g,CLSID\\{20D04F"
        $s5 = "23C2$C456$C2$78"
        $s6 = "ANSI_CHARSETDi"
        $s7 = "WWY]\\WlYpZlXt"
        $s8 = "p.h|#G;w85_!"
        $s9 = "CURRENT_USER"
        $s10 = "T!undArrayy"
    condition:
        pe.is_pe and
        pe.entry_point == 0x4BF20 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000D6B20 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xD745C and pe.data_directories[1].size == 0x330 and
        pe.data_directories[2].virtual_address == 0xD7000 and pe.data_directories[2].size == 0x45C and 
        pe.data_directories[9].virtual_address == 0xD6C90 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wsock32.dll", "send") and
        pe.imports("winspool.drv") and
        pe.imports("winspool.drv", "OpenPrinterA") and
        pe.imports("winmm.dll") and
        pe.imports("winmm.dll", "sndPlaySoundA") and
        pe.imports("wininet.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 7.9 and math.entropy(0, filesize) <= 8.0 and
        filesize >= 305 * 1024 and filesize <= 307 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        8 of ($s*)
}
rule Amitis_1_4_3b
{
    meta:
        description = "Detects Amitis_1_4_3b malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 60 48 00 8D BE 00 B0 F7 FF C7 87 10 17 0B 00 02 5B 1C 2A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 }
        $s1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s2 = "InternetGetConnectedState"
        $s3 = "LSID\\{20D04FE0-3AEA-102~"
        $s4 = "kernel32.dll^GetLongPqNq"
        $s5 = ".SCJ_LINES/Or@&y"
        $s6 = "69-A2D8-08002B30"
        $s7 = "VerQueryValueA"
        $s8 = "u0Nei.KHJ%NHJJ"
        $s9 = "1234567890ABCG"
        $s10 = "*U997-200]By"
    condition:
        pe.is_pe and
        pe.entry_point == 0x499B0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000CF5B0 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xD041C and pe.data_directories[1].size == 0x330 and
        pe.data_directories[2].virtual_address == 0xD0000 and pe.data_directories[2].size == 0x41C and 
        pe.data_directories[9].virtual_address == 0xCF720 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wsock32.dll", "send") and
        pe.imports("winspool.drv") and
        pe.imports("winspool.drv", "OpenPrinterA") and
        pe.imports("winmm.dll") and
        pe.imports("winmm.dll", "sndPlaySoundA") and
        pe.imports("wininet.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        pe.imports("gdi32.dll") and
        pe.imports("gdi32.dll", "SaveDC") and
        pe.imports("IMAGEHLP.DLL") and
        pe.imports("IMAGEHLP.DLL", "MapAndLoad") and
        math.entropy(0, filesize) >= 7.9 and math.entropy(0, filesize) <= 8.0 and
        filesize >= 296 * 1024 and filesize <= 298 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        9 of ($s*)
}
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
rule VanToM_W0rm_1_2
{
    meta:
        description = "Detects VanToM_W0rm_1_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "Microsoft.VisualBasic.CompilerServices"
        $s6 = "$7da4050a-ea26-46df-98a2-1ac25749dd20"
        $s7 = "UnmanagedFunctionPointerAttribute"
        $s8 = "SetCompatibleTextRenderingDefault"
        $s9 = "lpdwFirstCacheEntryInfoBufferSize"
        $s10 = "Microsoft.VisualBasic.MyServices"
    condition:
        pe.is_pe and
        pe.entry_point == 0x15F6E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00017B6E and //Optional Header's EP 
        pe.timestamp == 0x52869B3B and
        pe.data_directories[1].virtual_address == 0x17B20 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x1A000 and pe.data_directories[2].size == 0x3260 and
        pe.data_directories[5].virtual_address == 0x1E000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x18000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.6 and math.entropy(0, filesize) <= 5.7 and
        filesize >= 101 * 1024 and filesize <= 103 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x19800 and
        8 of ($s*)
}
rule Viral_Rat
{
    meta:
        description = "Detects Viral_Rat malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "System.Collections.Generic.IEqualityComparer<System.Diagnostics.StackFrame>.GetHashCode"
        $s2 = "CryptoObfuscatorHelper.MyExceptionReporting.ExceptionReportingConsentForm.resources"
        $s3 = "System.Collections.Generic.IEqualityComparer<System.Diagnostics.StackFrame>.Equals"
        $s4 = "System.Collections.Generic.IComparer<System.Reflection.Assembly>.Compare"
        $s5 = "System.Collections.Generic.IComparer<System.Diagnostics.Process>.Compare"
        $s6 = "A.ca9640b64dc00ee1c39ca7490fe956ef9"
        $s7 = "set_ColumnHeadersHeightSizeMode"
        $s8 = "!6LLRZZ\\ZZZ\\Z\\Z\\RRL3-!"
        $s9 = "ThreadStaticAttribute"
        $s10 = "btnSaveToFile_Click"
    condition:
        pe.is_pe and
        pe.entry_point == 0x34CEE and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00036AEE and//Optional Header's EP 
        pe.timestamp == 0x5466D5CB and
        pe.data_directories[1].virtual_address == 0x36A98 and pe.data_directories[1].size == 0x53 and
        pe.data_directories[2].virtual_address == 0x38000 and pe.data_directories[2].size == 0x48838 and
        pe.data_directories[5].virtual_address == 0x82000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 6.45 and math.entropy(0, filesize) <= 6.55 and
        filesize >= 501 * 1024 and filesize <= 503 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x7DA00 and
        9 of ($s*)
}
rule Vanguard_Remote_Administration_0_1_Beta
{
    meta:
        description = "Detects Vanguard_Remote_Administration_0_1_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 2E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 B0 AF 00 20 E8 5B 76 FF FF BE 30 D9 00 20 33 C0 55 68 84 B7 00 20 64 FF 30 64 89 20 68 07 80 00 00 E8 FE 78 FF FF B8 9C B7 00 20 E8 00 71 FF FF 8B D0 8B C6 B9 E4 00 00 00 E8 E6 7A FF FF E8 89 B0 FF FF 85 C0 75 07 C7 46 20 06 00 00 00 8D 55 EC 8B 46 20 E8 4B BF FF FF 8B 45 EC }
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
        $s2 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\~MHz"
        $s3 = ".SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        $s4 = "SYSTEM\\CurrentControlSet\\Services\\"
        $s5 = "Toolhelp32ReadProcessMemory"
        $s6 = "MakeSureDirectoryPathExists"
        $s7 = "InitializeProcessForWsWatch"
        $s8 = "user32.dll,LockWorkStation"
        $s9 = "UnhandledExceptionFilter"
        $s10 = "]</specialkey>"
    condition:
        pe.is_pe and
        pe.entry_point == 0xA478 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0000B078 and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xE000 and pe.data_directories[1].size == 0x109A and
        pe.data_directories[2].virtual_address == 0x13000 and pe.data_directories[2].size == 0x654 and 
        pe.data_directories[9].virtual_address == 0x11000 and pe.data_directories[9].size == 0x18 and
        pe.imports("kernel32.dll") and
        pe.imports("kernel32.dll", "OpenThread") and
        pe.imports("advpack.dll") and
        pe.imports("advpack.dll", "IsNTAdmin") and
        pe.imports("advapi32.dll") and
        pe.imports("advapi32.dll", "QueryServiceConfig2A") and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "SHGetSpecialFolderPathA") and
        pe.imports("user32.dll") and
        pe.imports("user32.dll", "CharNextA") and
        pe.imports("IMAGEHLP.DLL") and
        pe.imports("IMAGEHLP.DLL", "MakeSureDirectoryPathExists") and
        math.entropy(0, filesize) >= 6.1 and math.entropy(0, filesize) <= 6.2 and
        filesize >= 50 * 1024 and filesize <= 52 * 1024 and
        pe.overlay.size == 0 and // need to be comfirmed
        9 of ($s*)
}
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
rule Epsilon_RAT_v1_1
{
    meta:
        description = "Detects Epsilon_RAT_v1_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "$5a542c1b-2d36-4c31-b039-26a88d3967da"
        $s6 = "CRYPTPROTECT_PROMPT_ON_PROTECT" nocase
        $s7 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase
        $s8 = "Stub.Resources.resources"
        $s9 = "DOMAIN_VISIBLE_PASSWORD" nocase
        $s10 = "sqlite3_column_count" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x13FFE and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00015BFE and//Optional Header's EP 
        pe.timestamp == 0x534E0825 and
        pe.data_directories[1].virtual_address == 0x15BB0 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x18000 and pe.data_directories[2].size == 0xA68 and
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x16000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.65 and math.entropy(0, filesize) <= 5.72 and
        filesize >= 83 * 1024 and filesize <= 85 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x15200 and
        9 of ($s*)
}
rule Eagle_RAT_1_2
{
    meta:
        description = "Detects Eagle_RAT_1_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 10 00 00 00 20 00 00 80 18 00 00 00 D4 03 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 01 00 00 00 38 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "Microsoft.VisualBasic.ApplicationServices"
        $s3 = "Microsoft.VisualBasic.CompilerServices"
        $s4 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s5 = "$D8D715A3-6E5E-11D0-B3F0-00AA003761C5"
        $s6 = "$C6E13380-30AC-11d0-A18C-00A0C9118956" 
        $s7 = "$0000010c-0000-0000-C000-000000000046" 
        $s8 = "lpdwFirstCacheEntryInfoBufferSize"
        $s9 = "$56a868b3-0ad4-11ce-b03a-0020af0ba770" 
        $s10 = "$8f537d09-f85e-4414-b23b-502e54c79927" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x211D6 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00022FD6 and//Optional Header's EP 
        pe.timestamp == 0x51DF23C2 and
        pe.data_directories[1].virtual_address == 0x22F8C and pe.data_directories[1].size == 0x4A and
        pe.data_directories[2].virtual_address == 0x24000 and pe.data_directories[2].size == 0x8E4 and
        pe.data_directories[5].virtual_address == 0x26000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.86 and math.entropy(0, filesize) <= 5.88 and
        filesize >= 134 * 1024 and filesize <= 137 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x21E00 and
        9 of ($s*)
}
rule DH_Rat_0_3
{
    meta:
        description = "Detects DH_Rat_0_3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 30 F8 61 00 E8 44 05 DE FF A1 60 6E 63 00 8B 00 E8 C8 26 EB FF A1 60 6E 63 00 8B 00 B2 01 E8 F6 43 EB FF 8B 0D 08 71 63 00 A1 60 6E 63 00 8B 00 8B 15 14 71 61 00 E8 BA 26 EB FF A1 60 6E 63 00 8B 00 E8 FE 27 EB FF E8 AD BE DD FF 90 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 5B 00 36 00 33 00 36 00 38 00 36 00 31 00 37 00 35 00 5D 00 35 00 42 00 36 00 39 00 37 00 30 00 }
        $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s2 = "4!4%4)4-4145494=4A4E4I4M4Q4U4Y4]4a4e4i4m4q4u4y4}4"
        $s3 = "=a0CP4IW3IW2HW2HW2HW2HW2HW2HW2HW2HW2HW3IW4IW0CP"
        $s4 = "2$2(2,2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s5 = ">$>(>,>0>4>8><>@>D>H>L>P>T>X>\\>`>d>h>l>p>t>x>|>"
        $s6 = "9$9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s7 = "5&5*5.52565:5>5B5F5J5N5R5V5Z5^579A9H9O9Z9o9v9"
        $s8 = "(EIdAlreadyRegisteredAuthenticationMethod8/R"
        $s9 = "(TCustomGestureEngine.TGestureEngineFlags"
        $s10 = "(EIdAlreadyRegisteredAuthenticationMethod"
    condition:
        pe.is_pe and
        pe.entry_point == 0x228F70 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0022A770 and //Optional Header's EP 
        uint32(0x130) == 0x0022B000 and //Optional Header's Base of Data
        pe.timestamp == 0x52878373 and
        pe.data_directories[1].virtual_address == 0x23E000 and pe.data_directories[1].size == 0x3C1E and
        pe.data_directories[2].virtual_address == 0x26D000 and (pe.data_directories[2].size == 0x1EE48 or pe.data_directories[2].size == 0x20414) and
        pe.data_directories[5].virtual_address == 0x245000 and pe.data_directories[5].size == 0x27150 and
        pe.data_directories[9].virtual_address == 0x244000 and pe.data_directories[9].size == 0x18 and
        pe.imports("winmm.dll") and
        pe.imports("winmm.dll", "mciSendStringW") and
        pe.imports("winspool.drv") and
        pe.imports("winspool.drv", "GetDefaultPrinterW") and
        pe.imports("msimg32.dll") and
        pe.imports("msimg32.dll", "AlphaBlend") and
        math.entropy(0, filesize) >= 6.49 and math.entropy(0, filesize) <= 6.55 and
        filesize >= 2565 * 1024 and filesize <= 2575 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        (pe.overlay.offset == 0x281000 or pe.overlay.offset == 0x27FA00) and
        8 of ($s*)
}
rule OrionRAT_0_9
{
    meta:
        description = "Detects OrionRAT_0_9 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "26-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 56 B8 D4 6F 44 00 E8 9E F8 FB FF BB 98 5B 47 00 BE 60 5D 47 00 33 C0 55 68 9E 74 44 00 64 FF 30 64 89 20 B2 01 A1 48 CD 43 00 E8 42 CA FB FF 89 06 68 D0 07 00 00 E8 BA 72 FC FF B8 5C 5D 47 00 E8 E0 BC FF FF 84 C0 0F 84 F9 01 00 00 BA C8 5B 47 00 B9 64 00 00 00 A1 5C 5D 47 00 E8 A8 BD FF FF A1 C8 5B 47 00 E8 C2 FA }
        $s1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        $s2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\PATHSS"
        $s3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\MUTSS"
        $s4 = "8,84888<8@8D8H8L8P8T8X8\\8`8d8h8l8p8t8x8|8"
        $s5 = "$TMultiReadExclusiveWriteSynchronizer"
        $s6 = "4,4<4D4H4L4P4T4X4\\4`4d4h4l4p4t4x4|4"
        $s7 = "=$=(=0=4=<=@=H=L=T=X=`=d=l=p=x=|="
        $s8 = "\\Mozilla\\Firefox\\profiles.ini" nocase
        $s9 = "sqlite3_reset_auto_extension" nocase
        $s10 = "sqlite3_create_collation_v2" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x465D4 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000471D4 and//Optional Header's EP 
        uint32(0x130) == 0x00048000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x76000 and pe.data_directories[1].size == 0x1E88 and
        pe.data_directories[2].virtual_address == 0x7E000 and pe.data_directories[2].size >= 0x1C00  and pe.data_directories[2].size <= 0x1CFF  and
        pe.data_directories[5].virtual_address == 0x7A000 and pe.data_directories[5].size == 0x3C38 and
        pe.data_directories[9].virtual_address == 0x79000 and pe.data_directories[9].size == 0x18 and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        pe.imports("kernel32.dll") and
        pe.imports("kernel32.dll", "GetProcAddress") and
        pe.imports("SHFolder.dll") and
        pe.imports("SHFolder.dll", "SHGetFolderPathA") and
        pe.imports("crypt32.dll") and
        pe.imports("crypt32.dll", "CryptUnprotectData") and
        math.entropy(0, filesize) >= 7.15 and math.entropy(0, filesize) <= 7.30 and
        filesize >= 480 * 1024 and filesize <= 500 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}
rule Pandora_RAT_v1_1
{
    meta:
        description = "Detects Pandora_RAT_v1_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "26-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 56 B8 B4 DD 47 00 E8 16 8B F8 FF BB C4 26 48 00 BE 8C 28 48 00 33 C0 55 68 9E E3 47 00 64 FF 30 64 89 20 B2 01 A1 70 31 47 00 E8 D6 59 F8 FF 89 06 68 D0 07 00 00 E8 56 10 F9 FF B8 88 28 48 00 E8 F8 B2 FF FF 84 C0 0F 84 F9 01 00 00 BA F4 26 48 00 B9 64 00 00 00 A1 88 28 48 00 E8 68 B8 FF FF A1 F4 26 48 00 E8 6E F9 }
        $s1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        $s2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\PATHSS"
        $s3 = "8$8,8084888<8@8D8H8L8P8T8X8\\8`8d8h8l8p8t8x8|8"
        $s4 = "1!1%1)1-1115191=1A1E1I1M1Q1U1Y1]1a1e1i1m1q1u1y1}1"
        $s5 = "<(<,<4<8<<<@<D<H<L<P<T<X<\\<`<d<h<l<p<t<x<|<"
        $s6 = "HKEY_CURRENT_USER\\Software\\Microsoft\\MUTSS"
        $s7 = "7>8j899=9A9E9I9M9Q9U9Y9]9a9e9i9m9q9u9y9}9"
        $s8 = "$TMultiReadExclusiveWriteSynchronizer" 
        $s9 = ":$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:" 
        $s10 = ":>:B:F:J:N:R:V:Z:^:b:f:j:n:r:v:z:~:" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x7D4DC and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0007E0DC and //Optional Header's EP 
        uint32(0x130) == 0x0007F000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x83000 and pe.data_directories[1].size == 0x2CD2 and
        pe.data_directories[2].virtual_address == 0x90000 and pe.data_directories[2].size >= 0x53B0 and pe.data_directories[2].size >= 0x53DF and
        pe.data_directories[5].virtual_address == 0x88000 and pe.data_directories[5].size == 0x7250 and
        pe.data_directories[9].virtual_address == 0x87000 and pe.data_directories[9].size == 0x18 and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        pe.imports("ole32.dll") and
        pe.imports("ole32.dll", "CoInitializeEx") and
        pe.imports("ntdll.dll") and
        pe.imports("ntdll.dll", "RtlSetProcessIsCritical") and
        pe.imports("powrprof.dll") and
        pe.imports("powrprof.dll", "IsPwrShutdownAllowed") and
        math.entropy(0, filesize) >= 6.6 and math.entropy(0, filesize) <= 6.7 and
        filesize >= 570 * 1024 and filesize <= 575 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}
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
rule Kurd_Rat_v1_0_Beta_Online
{
    meta:
        description = "Detects Kurd_Rat_v1_0_Beta_Online malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 50 B8 42 00 00 00 00 00 00 00 00 00 24 B8 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXP" nocase
        $s3 = "Microsoft.VisualBasic.CompilerServices"
        $s4 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s5 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s6 = "$93E5A4E0-2D50-11d2-ABFA-00A0C9C6E38D" 
        $s7 = "$8f537d09-f85e-4414-b23b-502e54c79927" 
        $s8 = "$6B652FFF-11FE-4fce-92AD-0266B5D7C78F"
        $s9 = "$5a804648-4f66-4867-9c43-4f5c822cf1b8" 
        $s10 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase 
    condition:
        pe.is_pe and
        pe.entry_point == 0x29A42 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002B842 and//Optional Header's EP 
        uint32(0xB0) == 0x0002C000 and//Optional Header's Base of Data
        pe.timestamp == 0x51543BA3 and
        pe.data_directories[1].virtual_address == 0x2B7F4 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x4020 and
        pe.data_directories[5].virtual_address == 0x32000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.95 and math.entropy(0, filesize) <= 6.0 and
        filesize >= 182 * 1024 and filesize <= 187 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2E000 and
        9 of ($s*)
}
rule Furax_1_0b3
{
    meta:
        description = "Detects Furax_1_0b3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 6A FF 68 40 B3 40 00 68 38 A9 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 FC B1 40 00 59 83 0D 64 FA 40 00 FF 83 0D 68 FA 40 00 FF FF 15 F8 B1 40 00 8B 0D 5C FA 40 00 89 08 FF 15 F4 B1 40 00 8B 0D 58 FA 40 00 89 08 A1 F0 B1 40 00 8B 00 A3 60 FA 40 00 E8 98 9C FF FF 39 }
        
        $s1 = "0+1<1I1M1S1Z1_1e1i1n1s1y1}1"
        $s2 = "InitializeCriticalSection"
        $s3 = "GetDeviceDriverBaseNameA"
        $s4 = "KeServiceDescriptorTable"
        $s5 = "GetWindowThreadProcessId"
        $s6 = "CreateToolhelp32Snapshot" 
        $s7 = "6+6/63676;6?6C6G6K6i6" 
        $s8 = "SetCurrentDirectoryA"
        $s9 = "??1type_info@@UAE@XZ" 
        $s10 = "WaitForSingleObject" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x9BA6 and
        $EP at (pe.entry_point) and
        uint32(0x120) == 0x0000A7A6 and//Optional Header's EP 
        uint32(0x128) == 0x0000B000 and//Optional Header's Base of Data
        pe.timestamp == 0x430E2B79 and
        pe.data_directories[1].virtual_address == 0xB5C0 and pe.data_directories[1].size == 0xDC and
        pe.data_directories[2].virtual_address == 0x10000 and pe.data_directories[2].size == 0xF08 and
        pe.data_directories[5].virtual_address == 0x11000 and pe.data_directories[5].size == 0x810 and
        pe.data_directories[12].virtual_address == 0xB000 and pe.data_directories[12].size == 0x328 and
        pe.imports("MSVCRT.dll") and
        pe.imports("MSVCRT.dll", "_CxxThrowException") and
        pe.imports("SHLWAPI.dll") and
        pe.imports("SHLWAPI.dll", "SHDeleteKeyA") and
        pe.imports("WSOCK32.dll") and
        math.entropy(0, filesize) >= 6.4 and math.entropy(0, filesize) <= 6.7 and
        filesize >= 54 * 1024 and filesize <= 61 * 1024 and
        //no specified overlay string, all random 
        pe.overlay.offset == 0xDE00 and
        9 of ($s*)
}
rule Furax_1_0b2
{
    meta:
        description = "Detects Furax_1_0b2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 6A FF 68 38 B3 40 00 68 D8 A4 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 F0 B1 40 00 59 83 0D E4 F9 40 00 FF 83 0D E8 F9 40 00 FF FF 15 EC B1 40 00 8B 0D DC F9 40 00 89 08 FF 15 E8 B1 40 00 8B 0D D8 F9 40 00 89 08 A1 E4 B1 40 00 8B 00 A3 E0 F9 40 00 E8 22 01 00 00 39 }
        $s1 = ">#>(>.>2>7><>B>F>K>P>V>Z>_>d>"
        $s2 = "InitializeCriticalSection"
        $s3 = "0,030:0A0H0O0V0]0d0k0r0y0"
        $s4 = "KeServiceDescriptorTable"
        $s5 = "GetWindowThreadProcessId"
        $s6 = "NtAllocateVirtualMemory" 
        $s7 = "NtSetInformationProcess" 
        $s8 = "DeleteCriticalSection"
        $s9 = "NtWriteVirtualMemory" 
        $s10 = "??1type_info@@UAE@XZ" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x9746 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0000A346 and//Optional Header's EP 
        uint32(0x130) == 0x0000B000 and//Optional Header's Base of Data
        pe.timestamp == 0x42FF0DC9 and
        pe.data_directories[1].virtual_address == 0xB5B8 and pe.data_directories[1].size == 0xDC and
        pe.data_directories[2].virtual_address == 0x10000 and pe.data_directories[2].size == 0xF08 and
        pe.data_directories[5].virtual_address == 0x11000 and pe.data_directories[5].size == 0x7E4 and
        pe.data_directories[12].virtual_address == 0xB000 and pe.data_directories[12].size == 0x31C and
        pe.imports("MSVCRT.dll") and
        pe.imports("MSVCRT.dll", "_CxxThrowException") and
        pe.imports("SHLWAPI.dll") and
        pe.imports("SHLWAPI.dll", "SHDeleteKeyA") and
        pe.imports("WSOCK32.dll") and
        math.entropy(0, filesize) >= 6.4 and math.entropy(0, filesize) <= 6.7 and
        filesize >= 52 * 1024 and filesize <= 61 * 1024 and
        //no specified overlay string, all random 
        pe.overlay.offset == 0xD800 and
        9 of ($s*)
}
rule DDoSeR_3_4
{
    meta:
        description = "Detects DDoSeR_3_4 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "26-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 EC 53 33 C0 89 45 EC B8 A0 A2 41 00 E8 4E BF FE FF 33 C0 55 68 76 A4 41 00 64 FF 30 64 89 20 B2 01 A1 FC 6F 41 00 E8 F0 95 FE FF 8B D8 8B C3 E8 97 CE FF FF B8 78 C9 41 00 BA 8C A4 41 00 E8 44 A1 FE FF A1 78 C9 41 00 E8 8A F7 FF FF 68 B8 0B 00 00 E8 74 1D FF FF 68 98 A4 41 00 6A 00 6A 00 E8 1E C0 FE FF E8 F1 C0 FE FF 3D }
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "6(6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6"
        $s3 = "3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
        $s4 = "icon=%SystemRoot%\\system32\\SHELL32.dll,4"
        $s5 = "6,64686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6|6"
        $s6 = "$TMultiReadExclusiveWriteSynchronizer"
        $s7 = "1!1%1)1-1115191=1A1S1k1i3m3q3u3y3}3"
        $s8 = "8$8(80848<8@8H8L8T8X8`8d8l8p8x8|8" 
        $s9 = "sqlite3_bind_parameter_index" 
        $s10 = "\\Mozilla\\Firefox\\profiles.ini" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x19788 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0001A388 and //Optional Header's EP 
        uint32(0x130) == 0x0001B000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x1D000 and pe.data_directories[1].size == 0xF1E and
        pe.data_directories[2].virtual_address == 0x22000 and pe.data_directories[2].size >= 0x1400 and pe.data_directories[2].size <= 0x1600 and 
        pe.data_directories[5].virtual_address == 0x20000 and pe.data_directories[5].size == 0x1F38 and
        pe.data_directories[9].virtual_address == 0x1F000 and pe.data_directories[9].size == 0x18 and
        pe.imports("shell32.dll") and
        pe.imports("shell32.dll", "SHGetSpecialFolderPathA") and
        math.entropy(0, filesize) >= 6.44 and math.entropy(0, filesize) <= 6.54 and
        filesize >= 120 * 1024 and filesize <= 125 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}
rule Dark_Connect_v3_4
{
    meta:
        description = "Detects Dark_Connect_v3_4 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "26-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "Microsoft.VisualBasic.CompilerServices"
        $s6 = "$51e50cb0-04cb-4b2a-b1e3-3f94e716985f"
        $s7 = "PAPADDINGX" nocase
        $s8 = "v2.0.50727" 
        $s9 = "</assembly>" 
        $s10 = "System.ComponentModel.Design" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x2E4E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00004A4E and //Optional Header's EP 
        uint32(0xB0) == 0x00006000 and//Optional Header's Base of Data
        pe.timestamp == 0x55BA6B5F and
        pe.data_directories[1].virtual_address == 0x49F4 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x8000 and pe.data_directories[2].size == 0xE9F8 and 
        pe.data_directories[5].virtual_address == 0x18000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x6000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 7.72 and math.entropy(0, filesize) <= 7.82 and
        filesize >= 70 * 1024 and filesize <= 73 * 1024 and
        pe.overlay.size == 0 and 
        9 of ($s*)
}
rule AntiLamer_BackDoor_v1_1
{
    meta:
        description = "Detects AntiLamer_BackDoor_v1_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 70 44 00 8D BE 00 A0 FB FF C7 87 D0 C4 05 00 0F C4 C9 25 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 }
        //Found overlay hex are; 0D 0A 0D 0A  , 0D 0A   ,    0D 0A 0D 0A 0D 0A         
        $s1 = "TWARE\\Borland\\Delphi\\RTL"
        $s2 = "WNetEnumCachedPasswords"
        $s3 = "I_CHARSETDEFAULT5"
        $s4 = "GetLongPathNameA&"
        $s5 = "#t&<0t%<.t,<,t3"
        $s6 = "PORT_(^.SCJ_LI"
        $s7 = "GetProcAddress"
        $s8 = "sndPlaySoundA"
        $s9 = "ShellExecuteA"
        $s10 = "LMNO)STUVWXYZ"
    condition:
        pe.is_pe and
        pe.entry_point >= 0x28C00 and pe.entry_point <= 0x28D00 and
        $EP at (pe.entry_point) and
        uint32(0x128) >= 0x0006F800 and uint32(0x128) <= 0x0006F890 and    //Optional Header's EP 
        uint32(0x130) == 0x00070000 and 
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x70A04 and pe.data_directories[1].size == 0x2F0 and
        pe.data_directories[2].virtual_address == 0x70000 and pe.data_directories[2].size == 0xA04 and
        pe.data_directories[9].virtual_address >= 0x6F900 and pe.data_directories[9].virtual_address <= 0x6F9F0 and 
        pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wsock32.dll", "send") and
        pe.imports("winspool.drv") and
        pe.imports("winspool.drv", "OpenPrinterA") and
        pe.imports("winmm.dll") and
        pe.imports("winmm.dll", "sndPlaySoundA") and
        pe.imports("rasapi32.dll") and
        pe.imports("rasapi32.dll", "RasHangUpA") and
        math.entropy(0, filesize) >= 7.85 and math.entropy(0, filesize) <= 7.9 and
        filesize >= 165 * 1024 and filesize <= 170 * 1024 and
        //some samples have overlay, some not have.
        8 of ($s*)
}
rule AntiLamer_BackDoor_v1_2
{
    meta:
        description = "Detects AntiLamer_BackDoor_v1_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F4 B8 A0 B8 45 00 E8 B0 A8 FA FF A1 80 DB 45 00 8B 00 E8 24 82 FE FF 8B 0D F0 DC 45 00 A1 80 DB 45 00 8B 00 8B 15 7C 69 45 00 E8 24 82 FE FF A1 80 DB 45 00 8B 00 E8 98 82 FE FF E8 0B 7E FA FF 8D 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $EP2 = { 60 BE 00 90 44 00 8D BE 00 80 FB FF C7 87 D0 D4 05 00 DF C3 F6 16 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 }
        //$EP is not packed, $EP2 is packed(UPX)
        $Overlay = { 0D 0A } //Overlay start string
        $s1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "$TMultiReadExclusiveWriteSynchronizer"
        $s3 = "from=ALB&fromemail=Lamer@ALB.COM&subject="
        $s4 = "Software\\Borland\\Delphi\\Locales"
        $s5 = "====================54535"
        //first 5 string is from not packed
        //last 5 string is from packed(UPX)
        $s6 = "TWARE\\Borland\\Delphi\\RTL"
        $s7 = "WNetEnumCachedPasswords"
        $s8 = "GetLongPathNameA&"
        $s9 = "ANSI_CHARSETDEFA"
        $s10 = "#t&<0t%<.t,<,t3"
    condition:
        pe.is_pe and
        (pe.entry_point == 0x5AE50 or pe.entry_point == 0x292B0) and
        ($EP at (pe.entry_point) or $EP2 at (pe.entry_point)) and
        (uint32(0x128) == 0x0005BA50 or uint32(0x128) == 0x00071EB0 ) and//Optional Header's EP 
        pe.timestamp == 0x2A425E19 and
        (pe.data_directories[1].virtual_address == 0x5F000 and pe.data_directories[1].size == 0x2866 or pe.data_directories[1].virtual_address == 0x73A04 and pe.data_directories[1].size == 0x2F0) and
        (pe.data_directories[2].virtual_address == 0x6B000 and pe.data_directories[2].size == 0x3E00 or pe.data_directories[2].virtual_address == 0x73000 and pe.data_directories[2].size == 0xA04) and
        (pe.data_directories[9].virtual_address == 0x72020 and pe.data_directories[9].size == 0x18 or pe.data_directories[9].virtual_address == 0x63000 and pe.data_directories[9].size == 0x18) and
        pe.imports("KERNEL32.DLL") and
        pe.imports("comctl32.dll") and
        pe.imports("mpr.dll") and
        pe.imports("rasapi32.dll") and
        (math.entropy(0, filesize) >= 6.15 and math.entropy(0, filesize) <= 6.25 or math.entropy(0, filesize) >= 7.85 and math.entropy(0, filesize) <= 7.9) and
        (filesize >= 420 * 1024 and filesize <= 425 * 1024 or filesize >= 165 * 1024 and filesize <= 175 * 1024) and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        (pe.overlay.offset == 0x2A400 or pe.overlay.offset == 0x69A00)  and
        5 of ($s*)
}
rule ARC_v_4_2_0_0
{
    meta:
        description = "Detects ARC_v_4_2_0_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "<PrivateImplementationDetails>{3047EEC7-C613-4F17-8F84-690248EDB75B}"
        $s4 = "<Module>{7F28B7D6-CF7D-418D-8C16-F195651FA7CE}"
        $s5 = "$757e8318-2eb9-4658-a635-4466118b4946"
        $s6 = "8b2e54d3-c168-4c5b-b2f4-351321d03eb9"
        $s7 = "SetCompatibleTextRenderingDefault"
        $s8 = "__StaticArrayInitTypeSize=16"
        $s9 = "MD5CryptoServiceProvider"
        $s10 = "SLV0fFIsptsZtjvFft17"
    condition:
        pe.is_pe and
        pe.entry_point == 0x25D6E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002796E and//Optional Header's EP 
        uint32(0xB0) == 0x00028000 and//Optional Header's Base of Data
        pe.timestamp == 0x4CE91995 and
        pe.data_directories[1].virtual_address == 0x27920 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x2A000 and //There were no static Resource Directory Size 
        pe.data_directories[5].virtual_address == 0x2C000 and pe.data_directories[5].size == 0xC and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 7.2 and math.entropy(0, filesize) <= 7.3 and
        filesize >= 153 * 1024 and filesize <= 158 * 1024 and
        pe.overlay.size == 0 and 
        9 of ($s*)
}
rule BHF_Rat_v0_2_Beta
{
    meta:
        description = "Detects BHF_Rat_v0_2_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "$29c41831-494d-4bcf-93ea-14ce03a5553c"
        $s4 = "UnmanagedFunctionPointerAttribute"
        $s5 = "SetCompatibleTextRenderingDefault"
        $s6 = "lpdwFirstCacheEntryInfoBufferSize"
        $s7 = "Microsoft.VisualBasic.MyServices"
        $s8 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase
        $s9 = "AccessedThroughPropertyAttribute"
        $s10 = "System.Runtime.CompilerServices"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2089E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002249E and//Optional Header's EP 
        uint32(0xB0) == 0x00024000 and//Optional Header's Base of Data
        pe.timestamp == 0x54F58A46 and
        pe.data_directories[1].virtual_address == 0x22444 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x26000 and pe.data_directories[2].size == 0x2E78 and
        pe.data_directories[5].virtual_address == 0x2A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x24000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.65 and math.entropy(0, filesize) <= 5.75 and
        filesize >= 140 * 1024 and filesize <= 145 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x23E00 and
        9 of ($s*)
}
rule Bersek_1_0
{
    meta:
        description = "Detects Bersek_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { BE 00 70 42 00 8D BE 00 A0 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 }
        $Overlay = { 00 E0 00 0E 21 0B 01 06 00 00 C0 00 00 00 10 00 00 00 C0 03 00 40 8E 04 00 00 D0 03 00 00 90 04 00 00 00 00 10 00 10 00 00 00 02 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 A0 04 00 00 10 00 00 00 00 00 00 02 00 00 00 00 00 10 00 00 10 00 00 00 00 10 00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 90 04 }
        $s1 = "LoadLibraryAopenrSOFTWA"
        $s2 = "RE\\rcs\\Berzkpath$[unw"
        $s3 = "RE\\Microsoft\\Wiow"
        $s4 = "!o&RIGHUP]7LEFT"
        $s5 = "RLSHIFTAB_Capf"
        $s6 = "GetProcAddress"
        $s7 = "Toolhelp)Snap"
        $s8 = "ShellExecuteA" 
        $s9 = "CloseHandleO,"
        $s10 = "owunikeygeff"
    condition:
        pe.is_pe and
        pe.entry_point == 0x6ED1 and
        $EP at (pe.entry_point) and
        uint32(0x68) == 0x0002DCD1 and//Optional Header's EP 
        uint32(0x70) == 0x0002E000 and//Optional Header's Base of Data
        pe.timestamp == 0x4484B45F and
        pe.data_directories[1].virtual_address == 0x2E000 and pe.data_directories[1].size == 0x114 and
        pe.data_directories[2].virtual_address == 0x0 and pe.data_directories[2].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("ADVAPI32.dll") and
        pe.imports("ADVAPI32.dll", "RegCloseKey") and
        pe.imports("SHELL32.dll") and
        pe.imports("SHELL32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 7.83 and math.entropy(0, filesize) <= 7.88 and
        filesize >= 75 * 1024 and filesize <= 80 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        // pe.overlay.offset == 0x7200 and -----> idk why didn't work, Overlay offset is 0x7200 !!!!
        9 of ($s*)
}
rule Trochilus
{
    meta:
        description = "Detects Trochilus malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "27-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 30 91 40 00 33 F6 C6 44 24 14 20 FF 15 30 70 40 00 68 01 80 00 00 FF 15 B4 70 40 00 53 FF 15 7C 72 40 00 6A 08 A3 58 3F 42 00 E8 09 2C 00 00 A3 A4 3E 42 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 58 F4 41 00 FF 15 58 71 40 00 68 }
        $Overlay = { 02 00 00 00 EF BE AD DE 4E 75 6C 6C 73 6F 66 74 }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion"
        $s2 = "http://nsis.sf.net/NSIS_Error"
        $s3 = "WritePrivateProfileStringA"
        $s4 = "SHGetSpecialFolderLocation"
        $s5 = "LookupPrivilegeValueA"
        $s6 = "GetWindowsDirectoryA"
        $s7 = "WaitForSingleObject"
        $s8 = "MultiByteToWideChar"
        $s9 = "MessageBoxIndirectA"
        $s10 = "GetSystemDirectoryA"
    condition:
        pe.is_pe and
        pe.entry_point == 0x263C and
        $EP at (pe.entry_point) and
        uint32(0x100) == 0x0000323C and//Optional Header's EP 
        uint32(0x108) == 0x00007000 and//Optional Header's Base of Data
        pe.timestamp == 0x4B1AE3C6 and
        pe.data_directories[1].virtual_address == 0x73A4 and pe.data_directories[1].size == 0xB4 and
        pe.data_directories[2].virtual_address == 0x2C000 and pe.data_directories[2].size == 0x6C8 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("VERSION.dll") and
        pe.imports("COMCTL32.dll", "ImageList_Destroy") and
        math.entropy(0, filesize) >= 7.9 and math.entropy(0, filesize) <= 8.0 and
        filesize >= 320 * 1024 and filesize <= 330 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x7E00 and
        9 of ($s*)
}
rule Blue_Eye_v1_0b
{
    meta:
        description = "Detects Blue_Eye_v1_0b malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 }
        $s1 = "GetProcAddress"
        $s2 = "LoadLibraryA"
        $s3 = "KERNEL32.dll" nocase
        $s4 = "OKERN1L32" nocase 
        $s5 = "RXisutnr"
        $s6 = "Ydals=J"
        $s7 = "U@J9jRh"
        $s8 = "exQo9n:"
        $s9 = "!|$$LLh"
        $s10 = ">Softw"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2070 and
        $EP at (pe.entry_point) and
        uint32(0x34) == 0x00005E70 and//Optional Header's EP 
        uint32(0x3C) == 0x0000000C and//Optional Header's Base of Data
        pe.timestamp == 0x212E2E2E and
        pe.data_directories[1].virtual_address == 0x5F35 and pe.data_directories[1].size == 0x34 and
        pe.data_directories[2].virtual_address == 0x4000 and pe.data_directories[2].size == 0x15B8 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        math.entropy(0, filesize) >= 7.55 and math.entropy(0, filesize) <= 7.65 and
        filesize >= 6 * 1024 and filesize <= 10 * 1024 and
        //pe.overlay.size == 0 and  ------> There were hidden overlay probably
        7 of ($s*)
}
rule CobianRAT_v1_0_40_7
{
    meta:
        description = "Detects CobianRAT_v1_0_40_7 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "System.Runtime.Serialization.Formatters.Binary"
        $s5 = "$ab670678-0cae-4d28-9df7-df30c6109483"
        $s6 = "Dispose__Instance__"
        $s7 = "ComVisibleAttribute"
        $s8 = "Create__Instance__"
        $s9 = "DDDDDDDDDDDDDDp"
        $s10 = "B.My.Resources"
    condition:
        pe.is_pe and
        pe.entry_point >= 0x6A40 and pe.entry_point <= 0x6AC0 and
        $EP at (pe.entry_point) and
        uint32(0xA8) >= 0x00008840 and uint32(0xA8) <= 0x000088B0 and //Optional Header's EP 
        uint32(0xB0) == 0x00000000 and//Optional Header's Base of Data
         //no specific date //
        pe.data_directories[1].virtual_address >= 0x8800 and pe.data_directories[1].virtual_address <= 0x88FF and
        pe.data_directories[1].size >= 0x40 and pe.data_directories[1].size <= 0x60 and
        pe.data_directories[2].virtual_address == 0xA000 and pe.data_directories[2].size == 0xA00 and
        pe.data_directories[5].virtual_address == 0xC000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.45 and math.entropy(0, filesize) <= 5.55 and
        filesize >= 25 * 1024 and filesize <= 35 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
rule Daleth_RAT_1_0
{
    meta:
        description = "Detects Daleth_RAT_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 56 B8 50 3D 18 13 E8 22 2B FC FF BB C8 BB 18 13 BE 90 BD 18 13 33 C0 55 68 30 49 18 13 64 FF 30 64 89 20 B2 01 A1 B0 9F 17 13 E8 66 FC FB FF 89 06 68 40 49 18 13 E8 D2 2D FC FF 68 70 49 18 13 E8 C8 2D FC FF 68 98 49 18 13 E8 BE 2D FC FF 68 D0 07 00 00 E8 AC A2 FC FF B8 8C BD 18 13 E8 C2 B7 FF FF 84 C0 0F 84 F4 01 }
        $s1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        $s2 = "060:0>0B0F0J0N0R0V0Z0^0b0f0j0n0r0v0z0~0"
        $s3 = "$TMultiReadExclusiveWriteSynchronizer"
        $s4 = "E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E"
        $s5 = "1$1(10141<1@1H1L1T1X1`1d1l1p1x1|1"
        $s6 = "?$?,?0?4?8?<?@?D?H?L?X?x?"
        $s7 = "=$=,=4=<=D=L=T=\\=d=l=t=|="
        $s8 = "<$<,<4<<<D<L<T<\\<d<l<t<|<"
        $s9 = "UnhandledExceptionFilter"
        $s10 = "GetWindowThreadProcessId"
    condition:
        pe.is_pe and
        pe.entry_point == 0x43A48 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00044648 and //Optional Header's EP 
        uint32(0x130) == 0x00045000 and//Optional Header's Base of Data
        pe.timestamp == 0x4BCC379E and
        pe.data_directories[1].virtual_address == 0x4C000 and pe.data_directories[1].size == 0x214E and 
        pe.data_directories[2].virtual_address == 0x55000 and pe.data_directories[2].size >= 0x1B00 and pe.data_directories[2].size <= 0x1B30 and
        pe.data_directories[5].virtual_address == 0x51000 and pe.data_directories[5].size == 0x36C4 and
        pe.data_directories[9].virtual_address == 0x50000 and pe.data_directories[9].size == 0x18 and
        pe.imports("URLMON.DLL") and
        pe.imports("URLMON.DLL", "URLDownloadToFileA") and
        math.entropy(0, filesize) >= 6.6 and math.entropy(0, filesize) <= 6.7 and
        filesize >= 305 * 1024 and filesize <= 315 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
rule Dark_Virus_RAT_v0_2_0_Beta
{
    meta:
        description = "Detects Dark_Virus_RAT_v0_2_0_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "$4f44af02-8ca7-47bb-aff9-bb83508fab05"
        $s3 = "Microsoft.VisualBasic.CompilerServices"
        $s4 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s5 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s6 = "AssemblyTrademarkAttribute" 
        $s7 = "Stub.My.Resources" 
        $s8 = "AssemblyFileVersionAttribute"
        $s9 = "DebuggerStepThroughAttribute" 
        $s10 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase 
    condition:
        pe.is_pe and
        pe.entry_point == 0x1432E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00015F2E and//Optional Header's EP 
        uint32(0xB0) == 0x00016000 and//Optional Header's Base of Data
        pe.timestamp == 0x5301C997 and
        pe.data_directories[1].virtual_address == 0x15ED4 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x18000 and pe.data_directories[2].size == 0x248 and
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x16000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.72 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 80 * 1024 and filesize <= 85 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x14C00 and
        9 of ($s*)
}
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
rule Exception_1_0_Beta
{
    meta:
        description = "Detects Exception_1_0_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:   
        $EP = { 60 BE 00 ?? 40 00 8D BE 00 ?? FF FF 57 83 CD FF }
        $Overlay = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BE BE BE BE BE BE BE BE BE BE BE BE BE BE BE BE BE }
        $s1 = "GetProcAddress"
        $s2 = "ShellExecuteA"
        $s3 = "InternetOpenA"
        $s4 = "LoadLibraryA"
        $s5 = "KERNEL32.DLL" nocase
        $s6 = "ADVAPI32.dll" nocase
        $s7 = "WININET.dll" nocase
        $s8 = "WSOCK32.dll" nocase
        $s9 = "SHELL32.dll" nocase
        $s10 = "ExitProcess"
    condition:
        pe.is_pe and
        (pe.entry_point == 0x1A80 or pe.entry_point == 0x1AA0)  and
        $EP at (pe.entry_point) and
        (uint32(0x110) == 0x00007680 or uint32(0x118) == 0x000086A0 ) and//Optional Header's EP 
        (uint32(0x120) == 0x00009000 or uint32(0x118) == 0x00008000) and//Optional Header's Base of Data
        (pe.timestamp == 0x409CC16E or pe.timestamp == 0x409CC1F0) and
        (pe.data_directories[1].virtual_address == 0x8000 or pe.data_directories[1].virtual_address == 0x9F10) and pe.data_directories[1].size == 0x1A0 and
        pe.imports("WSOCK32.dll") and
        pe.imports("WININET.dll", "InternetOpenA") and
        math.entropy(0, filesize) >= 6.4 and math.entropy(0, filesize) <= 7.2 and
        filesize >= 7 * 1024 and filesize <= 13 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        (pe.overlay.offset == 0x1E00 or pe.overlay.offset == 0x2E00) and
        9 of ($s*)
}
rule THTRat
{
    meta:
        description = "Detects THTRat malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7F 30 D1 54 00 00 00 00 02 00 }
        $Overlay = { 7C 62 61 74 75 7C }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "Microsoft.VisualBasic.ApplicationServices"
        $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s4 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s5 = "$STATIC$FileTimeToDate$201112D10112C$lst"
        $s6 = "$STATIC$FileTimeToDate$201112D10112C$lft" 
        $s7 = "$789C1CBF-31EE-11D0-8C39-00C04FD9126B" 
        $s8 = "$5A6F1EC1-2DB1-11D0-8C39-00C04FD9126B"
        $s9 = "$5A6F1EC0-2DB1-11D0-8C39-00C04FD9126B" 
        $s10 = "$2210264d-e9d7-41fd-ad97-1e52353186dd"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2619E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x00027D9E and//Optional Header's EP 
        uint32(0xB0) == 0x00028000 and//Optional Header's Base of Data
        pe.timestamp == 0x54D1307F and
        pe.data_directories[1].virtual_address == 0x27D44 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x2A000 and pe.data_directories[2].size == 0x3B18 and
        pe.data_directories[5].virtual_address == 0x2E000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x28000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.3 and math.entropy(0, filesize) <= 5.8 and
        filesize >= 165 * 1024 and filesize <= 175 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x2A200 and
        9 of ($s*)
}
rule Exymna_RAT_v1_0
{
    meta:
        description = "Detects Exymna_RAT_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "System.Runtime.CompilerServices"
        $s2 = "WrapNonExceptionThrows"
        $s3 = "DllImportAttribute"
        $s4 = "v2.0.50727"
        $s5 = "OpenSubKey"
        $s6 = "output.exe" 
        $s7 = "GetProcesses" 
        $s8 = "ReadAllBytes"
        $s9 = "System.Drawing" 
        $s10 = "ProcessStartInfo"
    condition:
        pe.is_pe and
        pe.entry_point >= 0x24A0 and pe.entry_point <= 0x24EE and
        $EP at (pe.entry_point) and
        uint32(0xA8) >= 0x000042A0 and uint32(0xA8) <= 0x000042EE and//Optional Header's EP 
        uint32(0xB0) == 0x00006000 and//Optional Header's Base of Data
        // no specific date //
        pe.data_directories[1].virtual_address >= 0x4200 and pe.data_directories[1].virtual_address <= 0x42FF and
        pe.data_directories[1].size >= 0x40 and pe.data_directories[1].size <= 0x60 and
        pe.data_directories[2].virtual_address == 0x6000 and pe.data_directories[2].size == 0x2A0 and
        pe.data_directories[5].virtual_address == 0x8000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 4.5 and math.entropy(0, filesize) <= 5.0 and
        filesize >= 8 * 1024 and filesize <= 13 * 1024 and 
        pe.overlay.offset == 0x0 and
        7 of ($s*)
}
rule NanoCore_1_0_3_0
{
    meta:
        description = "Detects NanoCore_1_0_3_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "#=qyEe0p0oMg7P_uZnirjmfzla3OrsxrTW9ltaFIvDLbKEli_TP$A40MrfR8X6dRu62"
        $s3 = "#=qN6LsOpW6lRIEl4893xoFRlpUi2nIxVJ50VOHYYfjwF0KW$s3NqAIa6bj5$BiLl01"
        $s4 = "#=qJwXCDL1sRc5NCLx1rLrFbKBpdE4nIFpQ5ISUJgClxGB$nXyuH6F0mxGVcuMTc093"
        $s5 = "#=q5utOnzlzAIqBNkZpxhLcEf09C6yyWejs3Og87Ic4GkDt274oD8XGwu_GkmN$IBZG"
        $s6 = "#=q$YEx_Yyuv5eQaUJgJuZPelazaNvmULpLbgfvj$nbQfUdegrWOAfNzIgpLDDhRpnV"
        $s7 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s8 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s9 = "#=qzt5U5gDjyVKrEIvTWchfSqQTcExHKgazLffv$mI_DGE="
        $s10 = "#=qZRtmfEX2AgmTo5hDV5R8f4vjB_k5E8LI3QBKeKWO588="
    condition:
        pe.is_pe and
        pe.entry_point == 0x1285E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001465E and//Optional Header's EP 
        uint32(0xB0) == 0x00016000 and // Optional Header's Base of Data
        // no special date //
        pe.data_directories[5].virtual_address == 0x16000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[1].virtual_address == 0x14604 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x18000 and pe.data_directories[2].size >= 0x4BBB and pe.data_directories[2].size <= 0x4BFF and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 6.45 and math.entropy(0, filesize) <= 6.55 and
        filesize >= 90 * 1024 and filesize <= 100 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
rule NanoCore_1_2_2_0
{
    meta:
        description = "Detects NanoCore_1_2_2_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "#=qyEH54IW$f9fUJb7FOR8r3vj6e$onLGrpm2VGycjbl9TZJEqkwtA4y4bL9ExOWpiA"
        $s2 = "#=qXOmEbR_8DUzPz6sW4Kmd6kaKUIQOYZdTpvq2CkB17PTlG1zEUgI_P4skJXU2VwtO"
        $s3 = "#=qXkgpfghvTKDZGlXBGI4x9veQO4JfjF7GW2ECw9$L3EvyKZGOnziwXE2Xr1EkpRwe"
        $s4 = "#=qXjNBjXFhVcOvrRAG8alfq96_gJ4jOa0wwNOaztY3QjLWnMT6wXGDzBnHuUkef5N0"
        $s5 = "#=q3TG8MLoZf1Y44PREVW$6m76IGmuYE_BOhC_OTjkQJFtYWwRtSeFqevP9hiteuLfz"
        $s6 = "#=q4P_5NYDHZX9MPbDZuNFOAbRpAmJ2c_TFz8M5ulhIFApTRNfzn3_E1__1$MVw8$WV"
        $s7 = "#=q6Aboe3ONIkez7GgqcdWPi0_vrT_i53_89HUeagGM6MThXvFkvl8hpSeHO1UJawKN"
        $s8 = "#=q9c$dxNln4J1nxxC7UNVnfSKvSgKS421$zTS6z9ahlusddEno_MZclU7Qbfc$Fyw5"
        $s9 = "#=qCGokdf0OOxeMJLDkXSfc3NPmwygIQ29RjKQWj$wbNGB9C1pPgma_891QiNyTRXcA"
        $s10 = "#=qCoWHlVuoVRMkOzC7RZubJCslkxaEWn9yZiIydECf69$ktj0IPD5wAwC2H5Cc8C$L"
    condition:
        pe.is_pe and
        pe.entry_point == 0x1C992 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001E792 and//Optional Header's EP 
        uint32(0xB0) == 0x00020000 and // Optional Header's Base of Data
        pe.timestamp == 0x54E927A1 and
        pe.data_directories[5].virtual_address == 0x20000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[1].virtual_address == 0x1E738 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x22000 and pe.data_directories[2].size >= 0x15A00 and pe.data_directories[2].size <= 0x16A00 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 7.3 and math.entropy(0, filesize) <= 7.6 and
        filesize >= 200 * 1024 and filesize <= 210 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
rule NanoCore_RAT_Beta
{
    meta:
        description = "Detects NanoCore_RAT_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "#=qp4G0cT0V1Zbh4TTx$CCos2c9yAkNio2uugE29AEarJeRisgQqPCCGDMBjEzmBs$k"
        $s3 = "#=ql1RQWR3KcgcoSXP7w2ixnRt0_lNcVhyyu9mD5oYFDV$0WOhG1$VhGKUMJDT6QMAZ"
        $s4 = "#=qGZUG0ha3OYCsaWzdL89dbBjKjkMmMbwSWBWMEOQWV7JDjuu5CHmMMIWHcnYQzWmH"
        $s5 = "#=qcdGtSEQQ8L51fhaXOCMRRAquuuaSECfaYwPNx$jeIEouJ2EPb3QhbDJEd0XOfGkF"
        $s6 = "#=q4tyUzwGhLk3Ef4QQMP4tLTNQ$M6WCAS84CLIwA4BiEK6uhChLCNOCxEXImt9gqhz"
        $s7 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s8 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s9 = "#=qZsIA03esjCJfO25zx8wge0k98xHNSSX$9csygUgp93o="
        $s10 = "#=qZn_XWbpI5mNsp7b0R0yqvTNsNI3SUa8ioQ6iZDRizDs="
    condition:
        pe.is_pe and
        pe.entry_point == 0x1282A and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001462A and//Optional Header's EP 
        uint32(0xB0) == 0x00016000 and // Optional Header's Base of Data
        // no special date //
        pe.data_directories[5].virtual_address == 0x16000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[1].virtual_address == 0x145D0 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x18000 and pe.data_directories[2].size >= 0x4B00 and pe.data_directories[2].size <= 0x4BFF and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 6.45 and math.entropy(0, filesize) <= 6.55 and
        filesize >= 90 * 1024 and filesize <= 100 * 1024 and
        pe.overlay.size == 0 and 
        8 of ($s*)
}
rule NetAngel_v1_0
{
    meta:
        description = "Detects NetAngel_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 B8 3C 91 46 00 E8 B3 D0 F9 FF 8B 1D D0 B7 46 00 8B 03 E8 92 9A FE FF 8B 03 33 D2 E8 99 96 FE FF 8B 03 C6 40 5B 00 8B 0D 1C B9 46 00 8B 03 8B 15 D0 25 46 00 E8 88 9A FE FF 8B 0D 64 B9 46 00 8B 03 8B 15 F0 22 46 00 E8 75 9A FE FF 8B 03 E8 EE 9A FE FF 5B E8 BC B0 F9 FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "9$9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s3 = "2$2,2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s4 = "9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9"
        $s5 = "IsThemeBackgroundPartiallyTransparent"
        $s6 = "!TIdMappedPortOutboundConnectEvent"
        $s7 = "!EIdSocksServerNetUnreachableError"
        $s8 = "<<<D<H<L<P<T<X<\\<`<d<h<l<p<t<x<|<"
        $s9 = "WSAGetServiceClassNameByClassIdW"
        $s10 = "<$<(<,<0<4<8<<<@<D<H<L<P<\\<f<j<{<"
    condition:
        pe.is_pe and
        pe.entry_point == 0x6882C and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0006942C and//Optional Header's EP 
        uint32(0x130) == 0x0006A000 and // Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[5].virtual_address == 0x73000 and pe.data_directories[5].size == 0x807C and
        pe.data_directories[9].virtual_address == 0x72000 and pe.data_directories[9].size == 0x18 and
        pe.data_directories[1].virtual_address == 0x6E000 and pe.data_directories[1].size == 0x255C and
        pe.data_directories[2].virtual_address == 0x7C000 and pe.data_directories[2].size == 0xB600 and
        pe.imports("winmm.dll") and
        pe.imports("SHELL32.DLL", "SHEmptyRecycleBinA") and
        math.entropy(0, filesize) >= 6.55 and math.entropy(0, filesize) <= 6.65 and
        filesize >= 510 * 1024 and filesize <= 520 * 1024 and
        8 of ($s*)
}
rule Sinique_1_0
{
    meta:
        description = "Detects Sinique_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 E8 33 C0 89 45 E8 89 45 EC B8 B8 6B 40 00 E8 68 CD FF FF 33 C0 55 68 97 6C 40 00 64 FF 30 64 89 20 8D 55 EC B8 01 00 00 00 E8 19 BA FF FF 8B 45 EC BA AC 6C 40 00 E8 00 C6 FF FF 75 23 8D 45 E8 E8 12 E4 FF FF 8D 45 E8 BA BC 6C 40 00 E8 AD C4 FF FF 8B 45 E8 E8 95 C6 FF FF 50 E8 57 CE FF FF E8 3E EE FF FF E8 09 F3 FF FF E8 }
        $Overlay = { 8F A7 86 82 89 B9 AE A4 F4 F6 F4 F4 F4 F0 F4 FB F4 0B 0B F4 F4 4C F4 F4 F4 F4 F4 F4 F4 B4 F4 EE F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F4 F5 F4 F4 4E E4 F4 FA EB 40 FD 39 D5 4C F5 B8 39 D5 64 64 A0 9C 9D 87 D4 84 86 9B 93 86 95 99 D4 99 81 87 80 D4 96 91 D4 86 81 9A D4 81 9A }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "!0%0)0-0105090=0A0E0I0M0Q0U0Y0]0a0e0i0m0q0v0"
        $s3 = "||||||||||||||||||||||||||||"
        $s4 = "Toolhelp32ReadProcessMemory"
        $s5 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s6 = "InitializeProcessForWsWatch" 
        $s7 = "SHGetSpecialFolderLocation" 
        $s8 = "InitializeCriticalSection"
        $s9 = ";&;.;6;>;F;N;V;^;f;n;v;~;" 
        $s10 = "UnhandledExceptionFilter"
    condition:
        pe.is_pe and
        pe.entry_point == 0x6008 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00006C08 and//Optional Header's EP 
        uint32(0x130) == 0x00007000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x9000 and pe.data_directories[1].size == 0x7B4 and
        pe.data_directories[2].virtual_address == 0xD000 and pe.data_directories[2].size == 0xC00 and
        pe.data_directories[5].virtual_address == 0xC000 and pe.data_directories[5].size == 0x64C and
        pe.data_directories[9].virtual_address == 0xB000 and pe.data_directories[9].size == 0x18 and
        pe.imports("kernel32.dll") and
        pe.imports("shell32.dll", "SHGetPathFromIDListA") and
        math.entropy(0, filesize) >= 7.2 and math.entropy(0, filesize) <= 7.3 and
        filesize >= 60 * 1024 and filesize <= 65 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x8200 and
        9 of ($s*)
}
rule Slh
{
    meta:
        description = "Detects Slh malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 0F 00 00 00 6A 00 6A 00 49 75 F9 51 53 B8 BC 94 01 10 E8 C1 B0 FE FF 33 C0 55 68 CA 9A 01 10 64 FF 30 64 89 20 8D 45 E8 E8 AB 9C FF FF 8B 45 E8 8D 55 EC E8 D0 8D FF FF 8B 55 EC B8 94 DD 01 10 E8 83 A0 FE FF 8D 55 E0 33 C0 E8 8D 91 FE FF 8B 45 E0 8D 55 E4 E8 AE 8D FF FF 8B 45 E4 8B 15 94 DD 01 10 E8 F8 A2 FE FF 74 58 8D 55 }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "!0%0)0-0105090=0A0E0I0M0Q0U0Y0]0a0e0i0m0q0v0"
        $s3 = "||||||||||||||||||||||||||||"
        $s4 = "Toolhelp32ReadProcessMemory"
        $s5 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s6 = "InitializeProcessForWsWatch" 
        $s7 = "SHGetSpecialFolderLocation" 
        $s8 = "InitializeCriticalSection"
        $s9 = ";&;.;6;>;F;N;V;^;f;n;v;~;" 
        $s10 = "UnhandledExceptionFilter"
    condition:
        pe.is_pe and
        pe.entry_point == 0x189A4 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000195A4 and//Optional Header's EP 
        uint32(0x130) == 0x0001A000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x1E000 and pe.data_directories[1].size == 0x1338 and
        pe.data_directories[2].virtual_address == 0x24000 and pe.data_directories[2].size >= 0x900 and pe.data_directories[2].size <= 0xA00 and
        pe.data_directories[5].virtual_address == 0x22000 and pe.data_directories[5].size == 0x1538 and
        pe.data_directories[9].virtual_address == 0x21000 and pe.data_directories[9].size == 0x18 and
        pe.imports("WS2_32.DLL") and
        pe.imports("avicap32.dll", "capCreateCaptureWindowA") and
        math.entropy(0, filesize) >= 6.44 and math.entropy(0, filesize) <= 6.49 and
        filesize >= 120 * 1024 and filesize <= 125 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
rule Slh_2_0
{
    meta:
        description = "Detects Slh_2_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 0F 00 00 00 6A 00 6A 00 49 75 F9 53 B8 B8 FD 00 10 E8 DE 44 FF FF 33 C0 55 68 6C 03 01 10 64 FF 30 64 89 20 68 07 80 00 00 E8 AA 47 FF FF B8 84 03 01 10 E8 BC D2 FF FF 68 98 03 01 10 6A FF 6A 00 E8 02 46 FF FF A3 80 29 01 10 E8 B0 46 FF FF 3D B7 00 00 00 75 1D A1 80 29 01 10 50 E8 66 47 FF FF A1 80 29 01 10 50 E8 B3 45 FF }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\"
        $s3 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s4 = "Toolhelp32ReadProcessMemory"
        $s5 = "InitializeProcessForWsWatch"
        $s6 = "InitializeCriticalSection" 
        $s7 = "8&8.868>8F8N8V8^8f8n8v8~8" 
        $s8 = "7&7.767>7F7N7V7^7f7n7v7~7"
        $s9 = "6&6.666>6F6N6V6^6f6n6v6~6" 
        $s10 = "CreateToolhelp32Snapshot"
    condition:
        pe.is_pe and
        pe.entry_point == 0xF280 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0000FE80 and//Optional Header's EP 
        uint32(0x130) == 0x00011000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x13000 and pe.data_directories[1].size == 0x130C and
        pe.data_directories[2].virtual_address == 0x19000 and pe.data_directories[2].size >= 0x200 and pe.data_directories[2].size <= 0x300 and
        pe.data_directories[5].virtual_address == 0x18000 and pe.data_directories[5].size == 0xEB0 and
        pe.data_directories[9].virtual_address == 0x17000 and pe.data_directories[9].size == 0x18 and
        pe.imports("WS2_32.DLL") and
        pe.imports("kernel32.dll", "OpenThread") and
        math.entropy(0, filesize) >= 6.25 and math.entropy(0, filesize) <= 6.35 and
        filesize >= 70 * 1024 and filesize <= 80 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
rule Slh_3_0
{
    meta:
        description = "Detects Slh_3_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 16 00 00 00 6A 00 6A 00 49 75 F9 51 53 B8 C4 1A 01 10 E8 79 27 FF FF 33 C0 55 68 86 22 01 10 64 FF 30 64 89 20 68 E8 03 00 00 E8 95 2A FF FF 68 94 22 01 10 6A FF 6A 00 E8 AF 28 FF FF A3 A0 49 01 10 E8 6D 29 FF FF 3D B7 00 00 00 75 1D A1 A0 49 01 10 50 E8 23 2A FF FF A1 A0 49 01 10 50 E8 60 28 FF FF 6A 00 E8 C9 28 FF FF 68 }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\"
        $s3 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s4 = "Toolhelp32ReadProcessMemory"
        $s5 = ";.<f<m<H=L=P=T=X=\\=`=d=h=l=p=t=x=|="
        $s6 = "InitializeCriticalSection" 
        $s7 = "MakeSureDirectoryPathExists" 
        $s8 = "0&0,0L0T0X0\\0`0d0h0l0p0t0"
        $s9 = "AllowSetForegroundWindow" 
        $s10 = "NoPlugin|extension.dll"
    condition:
        pe.is_pe and
        pe.entry_point == 0x10F94 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00011B94 and//Optional Header's EP 
        uint32(0x130) == 0x00013000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x15000 and pe.data_directories[1].size == 0x13E2 and
        pe.data_directories[2].virtual_address == 0x1C000 and pe.data_directories[2].size >= 0x80 and pe.data_directories[2].size <= 0xFF and
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0x1150 and
        pe.data_directories[9].virtual_address == 0x19000 and pe.data_directories[9].size == 0x18 and
        pe.imports("advpack.dll") and
        pe.imports("urlmon", "URLDownloadToFileA") and
        math.entropy(0, filesize) >= 6.26 and math.entropy(0, filesize) <= 6.36 and
        filesize >= 78 * 1024 and filesize <= 88 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
rule Slh_4_0
{
    meta:
        description = "Detects Slh_4_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 3E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 94 52 15 13 E8 1B D5 FE FF BB 84 7D 15 13 33 C0 55 68 EC 5C 15 13 64 FF 30 64 89 20 68 07 80 00 00 E8 16 D8 FE FF B8 04 5D 15 13 E8 BC 7E FF FF 8D 45 EC E8 BC 51 FF FF 8B 55 EC B8 34 7E 15 13 E8 EB CB FE FF 83 3D 34 7E 15 13 00 75 0F B8 34 7E 15 13 BA 20 5D 15 13 E8 D3 CB FE }
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\"
        $s3 = "E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E"
        $s4 = "p|kkp]warAjv{Khm`oNnelnogNkzv2r"
        $s5 = "60686<6@6D6H6L6P6T6X6\\6`6d6r6z6"
        $s6 = "4(4044484<4@4D4H4L4P4T4X4\\4`4d4" 
        $s7 = "jmkrka{bdhjdq-ai)nq,l`ee8?<603" 
        $s8 = "http://www.assoftware.cjb.net"
        $s9 = "0,080<0@0D0H0L0P0T0b0j0r0z0" 
        $s10 = "7$7,7074787<7@7D7H7L7P7T7X7l7"
    condition:
        pe.is_pe and
        pe.entry_point == 0x1476C and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0001536C and//Optional Header's EP 
        uint32(0x130) == 0x00016000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x18000 and pe.data_directories[1].size == 0x142C and
        pe.data_directories[2].virtual_address == 0x1F000 and pe.data_directories[2].size >= 0x80 and pe.data_directories[2].size <= 0xFF and
        pe.data_directories[5].virtual_address == 0x1D000 and pe.data_directories[5].size == 0x1600 and
        pe.data_directories[9].virtual_address == 0x1C000 and pe.data_directories[9].size == 0x18 and
        pe.imports("IMAGEHLP.DLL") and
        pe.imports("advpack.dll", "IsNTAdmin") and
        math.entropy(0, filesize) >= 6.48 and math.entropy(0, filesize) <= 6.58 and
        filesize >= 95 * 1024 and filesize <= 105 * 1024 and
        pe.overlay.size == 0 and
        7 of ($s*)
}
rule SlickRAT_v1_0
{
    meta:
        description = "Detects SlickRAT_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "System.Runtime.InteropServices.ComTypes"
        $s6 = "Microsoft.VisualBasic.CompilerServices" 
        $s7 = "CRYPTPROTECT_PROMPT_ON_UNPROTECT" nocase 
        $s8 = "AccessedThroughPropertyAttribute"
        $s9 = "CompilationRelaxationsAttribute" 
        $s10 = "Me_Timer_Passed"
    condition:
        pe.is_pe and
        pe.entry_point == 0xEA2E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001062E and//Optional Header's EP 
        uint32(0xB0) == 0x00012000 and//Optional Header's Base of Data
        pe.timestamp == 0x4D594AA1 and
        pe.data_directories[1].virtual_address == 0x105E0 and pe.data_directories[1].size == 0x4B and
        pe.data_directories[2].virtual_address == 0x14000 and pe.data_directories[2].size >= 0x23A0 and pe.data_directories[2].size <= 0x23FF and
        pe.data_directories[5].virtual_address == 0x18000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x12000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.84 and math.entropy(0, filesize) <= 5.94 and
        filesize >= 64 * 1024 and filesize <= 74 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
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
rule Solitude_RAT_1_0
{
    meta:
        description = "Detects Solitude_RAT_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 06 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 B8 24 76 40 00 E8 18 B3 FF FF 33 C0 55 68 78 79 40 00 64 FF 30 64 89 20 E8 CD B4 FF FF E8 4C FE FF FF E8 5B FD FF FF 8D 45 EC 8B 15 B8 80 40 00 E8 75 A5 FF FF 8B 45 EC E8 11 FA FF FF 84 C0 75 07 6A 00 E8 5A B4 FF FF BA 88 79 40 00 B8 B0 80 40 00 E8 9F F9 FF FF 8B D8 B8 18 A0 40 00 }
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
        $s2 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot"
        $s3 = "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet003\\Control\\SafeBoot"
        $s4 = "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\SafeBoot"
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s6 = "6(6,6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" 
        $s7 = "Software\\Classes\\http\\shell\\open\\command\\" 
        $s8 = "htmlfile\\shell\\open\\command\\"
        $s9 = "Toolhelp32ReadProcessMemory" 
        $s10 = "http\\shell\\open\\command\\"
    condition:
        pe.is_pe and
        pe.entry_point == 0x6A9C and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0000769C and//Optional Header's EP 
        uint32(0x130) == 0x00008000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xB000 and pe.data_directories[1].size == 0x930 and
        pe.data_directories[2].virtual_address == 0xF000 and pe.data_directories[2].size >= 0x26000 and pe.data_directories[2].size <= 0x26FFF and
        pe.data_directories[5].virtual_address == 0xE000 and pe.data_directories[5].size == 0x574 and
        pe.data_directories[9].virtual_address == 0xD000 and pe.data_directories[9].size == 0x18 and
        pe.imports("shell32.dll") and
        pe.imports("user32.dll", "CharNextA") and
        math.entropy(0, filesize) >= 7.79 and math.entropy(0, filesize) <= 7.89 and
        filesize >= 181 * 1024 and filesize <= 191 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
rule TsuRat_v0_2
{
    meta:
        description = "Detects TsuRat_v0_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 EC 53 56 33 C0 89 45 EC B8 4C F8 43 00 E8 35 69 FC FF BB FC 2B 44 00 33 C0 55 68 8D FA 43 00 64 FF 30 64 89 20 68 E8 03 00 00 E8 48 D2 FC FF 8D 45 EC E8 90 7D FF FF 8B 45 EC E8 90 4D FC FF 50 6A FF 6A 00 E8 4E 6A FC FF 8B F0 85 F6 74 09 E8 3B 6B FC FF 85 C0 74 05 E8 BA 47 FC FF E8 29 BB FF FF A1 08 12 44 00 80 38 00 74 }
        $s1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDIN" nocase
        $s2 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString"
        $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\ProgramFilesDir"
        $s4 = "=!=%=)=-=1=5=9===A=E=I=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s6 = ";$;,;0;4;8;<;@;D;H;L;P;T;X;\\;`;d;h;l;p;t;x;|;" 
        $s7 = "$TMultiReadExclusiveWriteSynchronizer" 
        $s8 = "8$84888@8D8H8L8P8T8X8\\8`8d8h8l8p8t8"
        $s9 = ";!;%;);-;1;5;9;K;c;a=e=i=m=q=u=y=}=" 
        $s10 = "4$4(40444<4@4H4L4T4X4`4d4l4p4x4|4"
    condition:
        pe.is_pe and
        pe.entry_point == 0x3ED9C and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0003F99C and//Optional Header's EP 
        uint32(0x130) == 0x00040000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x43000 and pe.data_directories[1].size == 0x1A5E and
        pe.data_directories[2].virtual_address == 0x4B000 and pe.data_directories[2].size == 0x2128 and 
        pe.data_directories[5].virtual_address == 0x47000 and pe.data_directories[5].size == 0x3578 and
        pe.data_directories[9].virtual_address == 0x46000 and pe.data_directories[9].size == 0x18 and
        pe.imports("AVICAP32.DLL") and
        pe.imports("SHFolder.dll", "SHGetFolderPathA") and
        math.entropy(0, filesize) >= 6.51 and math.entropy(0, filesize) <= 6.61 and
        filesize >= 281 * 1024 and filesize <= 291 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
rule TsuRat_v0_3
{
    meta:
        description = "Detects TsuRat_v0_3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 0B 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 B8 F0 BE 40 00 E8 30 98 FF FF 8B 1D 4C D8 40 00 8B 35 0C D9 40 00 33 C0 55 68 BC C2 40 00 64 FF 30 64 89 20 8D 55 EC B8 01 00 00 00 E8 C1 6B FF FF 8B 45 EC BA D4 C2 40 00 E8 30 84 FF FF 75 71 8D 55 E4 33 C0 E8 A8 6B FF FF 8B 45 E4 8D 55 E8 E8 79 AE FF FF 8D 45 E8 BA E4 C2 40 00 E8 }
        $s1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDIN" nocase
        $s2 = "(&LLL&(LLL(,&LL&,(LL$(&%L!(&LL(!&LL(&!LL$&(%L!&(LL&!(LL&(!LL!&,(L!(,&L&,(!L(,&!L(,!&L&!,(L$(,&%$&,(%"
        $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\ProgramFilesDir"
        $s4 = "NM^^MpI~~c~,m`,ebxibxm~,ifioyxm~,i`,m~odezc,."
        $s5 = "7/7775111M1I1E1A1]1Y1U1Q1m1i1e1a1}1y1u1q1"
        $s6 = "NM^^MpBcan~i,oc~~ioxmaibxi,omanemhc,dm,." 
        $s7 = "cjxPEbxi~bix,It|`c~i~PAmebP_xm~x,\\mki" 
        $s8 = "8$84888@8D8H8L8P8T8X8\\8`8d8h8l8p8t8"
        $s9 = "6@0R0w0&121Z1Q142H2T2l2h2d2`2|2x2t2p2" 
        $s10 = ")*+$%&89:;456OHIJKDEF_XYZ[TUVohijkdef"
    condition:
        pe.is_pe and
        pe.entry_point == 0xB3A8 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0000BFA8 and//Optional Header's EP 
        uint32(0x130) == 0x0000D000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xF000 and pe.data_directories[1].size == 0xB9C and
        pe.data_directories[2].virtual_address == 0x13000 and pe.data_directories[2].size == 0x47D24 and 
        pe.data_directories[5].virtual_address == 0x12000 and pe.data_directories[5].size == 0xE9C and
        pe.data_directories[9].virtual_address == 0x11000 and pe.data_directories[9].size == 0x18 and
        pe.imports("advapi32.dll") and
        pe.imports("SHFolder.dll", "SHGetFolderPathA") and
        math.entropy(0, filesize) >= 6.74 and math.entropy(0, filesize) <= 6.84 and
        filesize >= 339 * 1024 and filesize <= 349 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
rule Tunnel_Rat_1_0
{
    meta:
        description = "Detects Tunnel_Rat_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 EC 33 C0 89 45 EC B8 B0 73 40 00 E8 9B C5 FF FF 33 C0 55 68 FB 74 40 00 64 FF 30 64 89 20 E8 A4 CF FF FF E8 C3 D1 FF FF E8 46 F8 FF FF E8 35 F7 FF FF 8B 15 E8 9B 40 00 A1 E4 9B 40 00 E8 CD F0 FF FF 33 C9 BA 10 75 40 00 B8 02 00 00 80 E8 98 CC FF FF 8D 45 EC E8 88 EF FF FF 8D 45 EC BA 80 75 40 00 E8 33 BD FF FF 8B 45 EC }
        $s1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall" 
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        $s4 = "187<7@7D7H7L7P7T7X7\\7`7d7h7l7p7t7x7|7"
        $s5 = "0123456789abcdefghijklmnopqrstuvxyz"
        $s6 = "E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E`E" 
        $s7 = "InitializeCriticalSection" 
        $s8 = ";&;.;6;>;F;N;V;^;f;n;v;~;"
        $s9 = "UnhandledExceptionFilter" 
        $s10 = "System32\\drivers\\Pws.dat"
    condition:
        pe.is_pe and
        pe.entry_point == 0x6850 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00007450 and//Optional Header's EP 
        uint32(0x130) == 0x00008000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xA000 and pe.data_directories[1].size == 0x664 and
        pe.data_directories[2].virtual_address == 0xE000 and pe.data_directories[2].size == 0x3D800 and 
        pe.data_directories[5].virtual_address == 0xD000 and pe.data_directories[5].size == 0x78C and
        pe.data_directories[9].virtual_address == 0xC000 and pe.data_directories[9].size == 0x18 and
        pe.imports("kernel32.dll") and
        pe.imports("shell32.dll", "FindExecutableA") and
        math.entropy(0, filesize) >= 7.24 and math.entropy(0, filesize) <= 7.34 and
        filesize >= 274 * 1024 and filesize <= 284 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
rule TiG3R_RAT_v1_0
{
    meta:
        description = "Detects TiG3R_RAT_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AF F0 6F 52 00 00 00 00 02 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" 
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "Microsoft.VisualBasic.CompilerServices"
        $s6 = "$8c0a0be4-c2d9-43fd-8362-d331a08ed069" 
        $s7 = "UnmanagedFunctionPointerAttribute" 
        $s8 = "SetCompatibleTextRenderingDefault"
        $s9 = "Microsoft.VisualBasic.MyServices" 
        $s10 = "lpdwFirstCacheEntryInfoBufferSize"
    condition:
        pe.is_pe and
        pe.entry_point == 0x13D9E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001599E and//Optional Header's EP 
        uint32(0xB0) == 0x00016000 and//Optional Header's Base of Data
        pe.timestamp == 0x526FF0AF and
        pe.data_directories[1].virtual_address == 0x1594C and pe.data_directories[1].size == 0x4F and
        pe.data_directories[2].virtual_address == 0x18000 and pe.data_directories[2].size == 0xA28 and 
        pe.data_directories[5].virtual_address == 0x1A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x16000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.69 and math.entropy(0, filesize) <= 5.79 and
        filesize >= 78 * 1024 and filesize <= 88 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x14E00 and
        9 of ($s*)
}
rule VorteX_RAT
{
    meta:
        description = "Detects VorteX_RAT malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 53 56 B8 EC E6 43 00 E8 D2 82 FC FF BB 7C 1A 44 00 BE 44 1C 44 00 33 C0 55 68 DA EA 43 00 64 FF 30 64 89 20 B2 01 A1 88 83 43 00 E8 F2 54 FC FF 89 06 8B 06 C6 40 08 00 68 E8 EA 43 00 E8 DC 85 FC FF 68 D0 07 00 00 E8 7E EC FC FF B8 40 1C 44 00 E8 78 D2 FF FF 84 C0 0F 84 C5 01 00 00 BA AC 1A 44 00 B9 64 00 00 00 A1 40 }
        $s1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" 
        $s2 = ";.;2;6;:;>;B;F;J;N;R;V;Z;^;b;f;??I?P?W?b?w?~?"
        $s3 = "4(4044484<4@4D4H4L4P4T4X4\\4`4d4h4l4p4t4x4|4"
        $s4 = "6!6%6)6-6165696=6A6E6I6M6Q6U6Y6]6a6e6i6=8"
        $s5 = "9$9(90949@9D9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s6 = "6(6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6|6" 
        $s7 = "2:3>3B3F3J3N3R3V3Z3^3b3f3j3n3r3v3z3~3" 
        $s8 = "$TMultiReadExclusiveWriteSynchronizer"
        $s9 = "2$242<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2" 
        $s10 = "1$1(1,1014181<1@1D1H1L1P1Z1^1p1"
    condition:
        pe.is_pe and
        pe.entry_point == 0x3DC34 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0003E834 and//Optional Header's EP 
        uint32(0x130) == 0x0003F000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x42000 and pe.data_directories[1].size == 0x198A and
        pe.data_directories[2].virtual_address == 0x4A000 and pe.data_directories[2].size >= 0x1A80 and pe.data_directories[2].size <= 0x1AFF and
        pe.data_directories[5].virtual_address == 0x46000 and pe.data_directories[5].size == 0x338C and
        pe.data_directories[9].virtual_address == 0x45000 and pe.data_directories[9].size == 0x18 and
        pe.imports("URLMON.DLL") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.53 and math.entropy(0, filesize) <= 6.63 and
        filesize >= 275 * 1024 and filesize <= 285 * 1024 and
        pe.overlay.size == 0 and
        9 of ($s*)
}
rule wiRAT
{
    meta:
        description = "Detects wiRAT malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 71 77 65 72 74 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" 
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "Microsoft.VisualBasic.ApplicationServices"
        $s5 = "Microsoft.VisualBasic.CompilerServices"
        $s6 = "$STATIC$GetRandom$202888$Generator$Init" 
        $s7 = "set_CheckForIllegalCrossThreadCalls" 
        $s8 = "$da06ac9c-ad06-4559-b6b4-0cd4c771e49f"
        $s9 = "TripleDESCryptoServiceProvider" 
        $s10 = "Wi_Rat.Resources.resources" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x17D4E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0001994E and//Optional Header's EP 
        uint32(0xB0) == 0x0001A000 and//Optional Header's Base of Data
        pe.timestamp == 0x534EA4d5 and
        pe.data_directories[1].virtual_address == 0x198F8 and pe.data_directories[1].size == 0x53 and
        pe.data_directories[2].virtual_address == 0x1C000 and pe.data_directories[2].size == 0x3B60 and 
        pe.data_directories[5].virtual_address == 0x20000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x1A000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.67 and math.entropy(0, filesize) <= 5.77 and
        filesize >= 106 * 1024 and filesize <= 116 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x1BE00 and
        9 of ($s*)
}
rule Z_dem0n10
{
    meta:
        description = "Detects Z_dem0n10 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 F0 5B 4A 00 E8 BC 0E F6 FF A1 68 8A 4A 00 8B 00 E8 04 25 FB FF 8B 0D F4 86 4A 00 A1 68 8A 4A 00 8B 00 8B 15 BC B0 49 00 E8 04 25 FB FF A1 68 8A 4A 00 8B 00 E8 78 25 FB FF E8 FB E7 F5 FF 8D 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" 
        $s2 = "System\\CurrentControlSet\\Control\\Print\\Printers"
        $s3 = "from=Z-dem0n&fromemail=Z-dem0n@xxx.net&subject="
        $s4 = "3$3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
        $s5 = "Hardware\\Description\\System\\CentralProcessor\\0"
        $s6 = "system\\CurrentControlSet\\Services\\VxD\\VNETSUP" 
        $s7 = "=)>->1>5>9>=>A>E>I>M>Q>U>Y>]>a>e>i>m>q>u>y>}>" 
        $s8 = ">(>0>4>8><>@>D>H>L>P>T>X>\\>`>d>h>l>p>t>x>|>"
        $s9 = "-----------PASSWORDS----------------------" 
        $s10 = "-----------UINs----------------------" 
    condition:
        pe.is_pe and
        pe.entry_point == 0xA52E0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000A5EE0 and//Optional Header's EP 
        uint32(0x130) == 0x000A6000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xAB000 and pe.data_directories[1].size == 0x2D98 and
        pe.data_directories[2].virtual_address == 0xBA000 and pe.data_directories[2].size == 0x8600 and 
        pe.data_directories[5].virtual_address == 0xB0000 and pe.data_directories[5].size == 0x9DBC and
        pe.data_directories[9].virtual_address == 0xAF000 and pe.data_directories[9].size == 0x18 and
        pe.imports("rasapi32.dll") and
        pe.imports("mpr.dll", "WNetEnumCachedPasswords") and
        math.entropy(0, filesize) >= 6.58 and math.entropy(0, filesize) <= 6.68 and
        filesize >= 752 * 1024 and filesize <= 762 * 1024 and
        9 of ($s*)
}
rule Z_dem0n12
{
    meta:
        description = "Detects Z_dem0n12 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 50 BA 4A 00 E8 EC B0 F5 FF A1 34 E0 4A 00 8B 00 E8 18 C7 FA FF A1 34 E0 4A 00 8B 00 33 D2 E8 16 C3 FA FF 8B 0D A8 DC 4A 00 A1 34 E0 4A 00 8B 00 8B 15 A4 F6 49 00 E8 0A C7 FA FF A1 34 E0 4A 00 8B 00 E8 7E C7 FA FF E8 0D 8A F5 FF 90 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" 
        $s2 = "System\\CurrentControlSet\\Control\\Print\\Printers"
        $s3 = "from=Z-dem0n&fromemail=Z-dem0n@xxx.net&subject="
        $s4 = "TAdvancedMenuDrawItemEvent"
        $s5 = "Hardware\\Description\\System\\CentralProcessor\\0"
        $s6 = "system\\CurrentControlSet\\Services\\VxD\\VNETSUP" 
        $s7 = "--------------------------------------------" 
        $s8 = "=,=0=4=8=<=@=D=H=L=P=T=X=\\=`=d=h=l=p=t=x=|="
        $s9 = "-----------PASSWORDS----------------------" 
        $s10 = "-----------UINs----------------------" 
    condition:
        pe.is_pe and
        pe.entry_point == 0xAB140 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000ABD40 and//Optional Header's EP 
        uint32(0x130) == 0x000AC000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xB1000 and pe.data_directories[1].size == 0x2DB6 and
        pe.data_directories[2].virtual_address == 0xC1000 and pe.data_directories[2].size == 0x6C00 and 
        pe.data_directories[5].virtual_address == 0xB6000 and pe.data_directories[5].size == 0xA210 and
        pe.data_directories[9].virtual_address == 0xB5000 and pe.data_directories[9].size == 0x18 and
        pe.imports("rasapi32.dll") and
        pe.imports("iphlpapi.dll", "GetNetworkParams") and
        math.entropy(0, filesize) >= 6.58 and math.entropy(0, filesize) <= 6.68 and
        filesize >= 768 * 1024 and filesize <= 778 * 1024 and
        9 of ($s*)
}
rule Z_dem0n111
{
    meta:
        description = "Detects Z_dem0n111 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 B8 8C 4A 00 E8 64 DE F5 FF A1 EC BF 4A 00 8B 00 E8 64 F4 FA FF A1 EC BF 4A 00 8B 00 33 D2 E8 62 F0 FA FF 8B 0D 78 BC 4A 00 A1 EC BF 4A 00 8B 00 8B 15 8C E9 49 00 E8 56 F4 FA FF A1 EC BF 4A 00 8B 00 E8 CA F4 FA FF E8 95 B7 F5 FF 90 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" 
        $s2 = "System\\CurrentControlSet\\Control\\Print\\Printers"
        $s3 = "from=Z-dem0n&fromemail=Z-dem0n@xxx.net&subject="
        $s4 = "TAdvancedMenuDrawItemEvent"
        $s5 = "Hardware\\Description\\System\\CentralProcessor\\0"
        $s6 = "system\\CurrentControlSet\\Services\\VxD\\VNETSUP" 
        $s7 = "--------------------------------------------" 
        $s8 = "=,=0=4=8=<=@=D=H=L=P=T=X=\\=`=d=h=l=p=t=x=|="
        $s9 = "-----------PASSWORDS----------------------" 
        $s10 = "-----------UINs----------------------" 
    condition:
        pe.is_pe and
        pe.entry_point == 0xA83B8 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000A8FB8 and//Optional Header's EP 
        uint32(0x130) == 0x000AA000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xAF000 and pe.data_directories[1].size == 0x2D16 and
        pe.data_directories[2].virtual_address == 0xBF000 and pe.data_directories[2].size == 0x8600 and 
        pe.data_directories[5].virtual_address == 0xB4000 and pe.data_directories[5].size == 0xA008 and
        pe.data_directories[9].virtual_address == 0xB3000 and pe.data_directories[9].size == 0x18 and
        pe.imports("rasapi32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.59 and math.entropy(0, filesize) <= 6.69 and
        filesize >= 763 * 1024 and filesize <= 773 * 1024 and
        9 of ($s*)
}
rule Z_dem0n126
{
    meta:
        description = "Detects Z_dem0n126 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 F8 F7 4A 00 E8 48 73 F5 FF A1 8C 20 4B 00 8B 00 E8 A4 A6 FA FF A1 8C 20 4B 00 8B 00 33 D2 E8 A2 A2 FA FF 8B 0D E4 1C 4B 00 A1 8C 20 4B 00 8B 00 8B 15 C0 18 4A 00 E8 96 A6 FA FF A1 8C 20 4B 00 8B 00 E8 0A A7 FA FF E8 69 4C F5 FF 90 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" 
        $s2 = "System\\CurrentControlSet\\Control\\Print\\Printers"
        $s3 = "from=Z-dem0n&fromemail=Z-dem0n@xxx.net&subject="
        $s4 = "TAdvancedMenuDrawItemEvent"
        $s5 = "Hardware\\Description\\System\\CentralProcessor\\0"
        $s6 = "system\\CurrentControlSet\\Services\\VxD\\VNETSUP" 
        $s7 = "--------------------------------------------" 
        $s8 = "=,=0=4=8=<=@=D=H=L=P=T=X=\\=`=d=h=l=p=t=x=|="
        $s9 = "-----------PASSWORDS----------------------" 
        $s10 = "-----------UINs----------------------" 
    condition:
        pe.is_pe and
        pe.entry_point == 0xAEEF0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000AFAF0 and//Optional Header's EP 
        uint32(0x130) == 0x000B0000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xB5000 and pe.data_directories[1].size == 0x2E08 and
        pe.data_directories[2].virtual_address == 0xC5000 and pe.data_directories[2].size == 0x7000 and 
        pe.data_directories[5].virtual_address == 0xBA000 and pe.data_directories[5].size == 0xA72C and
        pe.data_directories[9].virtual_address == 0xB9000 and pe.data_directories[9].size == 0x18 and
        pe.imports("rasapi32.dll") and
        pe.imports("shell32.dll", "ShellExecuteA") and
        math.entropy(0, filesize) >= 6.59 and math.entropy(0, filesize) <= 6.69 and
        filesize >= 786 * 1024 and filesize <= 796 * 1024 and
        9 of ($s*)
}
rule SilentSpy_2_0_1
{
    meta:
        description = "Detects SilentSpy_2_0_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 B0 6F 47 00 E8 74 F9 F8 FF A1 CC 98 47 00 8B 00 E8 58 11 FE FF 8B 0D 00 98 47 00 A1 CC 98 47 00 8B 00 8B 15 A8 48 47 00 E8 58 11 FE FF A1 CC 98 47 00 8B 00 E8 CC 11 FE FF E8 DF D3 F8 FF 8D 40 00 00 00 00 00 00 00 00 00 }
        $s1 = "3$3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" 
        $s2 = "1$1(1,1014181<1@1D1H1L1P1T1X1\\1`1d1h1l1p1t1x1|1"
        $s3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s4 = "8-9195999=9A9E9I9M9Q9U9Y9]9a9e9i9m9q9u9y9}9"
        $s5 = "2(2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s6 = "6$60646<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" 
        $s7 = "ImmSetCompositionWindow" 
        $s8 = "$TMultiReadExclusiveWriteSynchronizer"
        $s9 = "http://www.microsoft.com/" 
        $s10 = "InitializeCriticalSection" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x76578 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00077178 and//Optional Header's EP 
        uint32(0x130) == 0x00078000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x7B000 and pe.data_directories[1].size == 0x2764 and
        pe.data_directories[2].virtual_address == 0x88000 and pe.data_directories[2].size == 0x4400 and 
        pe.data_directories[5].virtual_address == 0x80000 and pe.data_directories[5].size == 0x7198 and
        pe.data_directories[9].virtual_address == 0x7F000 and pe.data_directories[9].size == 0x18 and
        pe.imports("winmm.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 6.56 and math.entropy(0, filesize) <= 6.66 and
        filesize >= 531 * 1024 and filesize <= 541 * 1024 and
        9 of ($s*)
}
rule SilentSpy_2_0_0
{
    meta:
        description = "Detects SilentSpy_2_0_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 CC 6F 47 00 E8 58 F9 F8 FF A1 CC 98 47 00 8B 00 E8 3C 11 FE FF 8B 0D 00 98 47 00 A1 CC 98 47 00 8B 00 8B 15 C0 48 47 00 E8 3C 11 FE FF A1 CC 98 47 00 8B 00 E8 B0 11 FE FF E8 C3 D3 F8 FF 8D 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s1 = "3$3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" 
        $s2 = "1$1(1,1014181<1@1D1H1L1P1T1X1\\1`1d1h1l1p1t1x1|1"
        $s3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s4 = "8-9195999=9A9E9I9M9Q9U9Y9]9a9e9i9m9q9u9y9}9"
        $s5 = "2(2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s6 = "6$60646<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" 
        $s7 = "ImmSetCompositionWindow" 
        $s8 = "$TMultiReadExclusiveWriteSynchronizer"
        $s9 = "http://www.microsoft.com/" 
        $s10 = "InitializeCriticalSection" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x76594 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00077194 and//Optional Header's EP 
        uint32(0x130) == 0x00078000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x7B000 and pe.data_directories[1].size == 0x27A8 and
        pe.data_directories[2].virtual_address == 0x88000 and pe.data_directories[2].size == 0x4400 and 
        pe.data_directories[5].virtual_address == 0x80000 and pe.data_directories[5].size == 0x7194 and
        pe.data_directories[9].virtual_address == 0x7F000 and pe.data_directories[9].size == 0x18 and
        pe.imports("winmm.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 6.56 and math.entropy(0, filesize) <= 6.66 and
        filesize >= 531 * 1024 and filesize <= 541 * 1024 and
        9 of ($s*)
}
rule SilentSpy_2_1_0
{
    meta:
        description = "Detects SilentSpy_2_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F0 B8 A0 90 47 00 E8 6C D8 F8 FF 68 F0 92 47 00 6A 00 6A 00 E8 DA D9 F8 FF E8 CD DA F8 FF 3D B7 00 00 00 75 0E A1 D8 B8 47 00 8B 00 E8 6A 03 FE FF EB 30 A1 D8 B8 47 00 8B 00 E8 D8 01 FE FF 8B 0D 08 B8 47 00 A1 D8 B8 47 00 8B 00 8B 15 70 60 47 00 E8 D8 01 FE FF A1 D8 B8 47 00 8B 00 E8 4C 02 FE FF E8 AF B2 F8 FF 00 00 00 }
        $s1 = "3$3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" 
        $s2 = "1$1(1,1014181<1@1D1H1L1P1T1X1\\1`1d1h1l1p1t1x1|1"
        $s3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s4 = "8-9195999=9A9E9I9M9Q9U9Y9]9a9e9i9m9q9u9y9}9"
        $s5 = "2(2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s6 = "6$60646<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" 
        $s7 = "ImmSetCompositionWindow" 
        $s8 = "$TMultiReadExclusiveWriteSynchronizer"
        $s9 = "http://www.microsoft.com/" 
        $s10 = "InitializeCriticalSection" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x78680 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00079280 and//Optional Header's EP 
        uint32(0x130) == 0x0007A000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x7D000 and pe.data_directories[1].size == 0x28CA and
        pe.data_directories[2].virtual_address == 0x8A000 and pe.data_directories[2].size == 0x4600 and 
        pe.data_directories[5].virtual_address == 0x82000 and pe.data_directories[5].size == 0x7388 and
        pe.data_directories[9].virtual_address == 0x81000 and pe.data_directories[9].size == 0x18 and
        pe.imports("winmm.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 6.56 and math.entropy(0, filesize) <= 6.66 and
        filesize >= 541 * 1024 and filesize <= 551 * 1024 and
        7 of ($s*)
}
rule ToRAT_v0_2_1
{
    meta:
        description = "Detects ToRAT_v0_2_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { E8 B5 D0 00 00 E9 7F FE FF FF CC CC CC CC CC CC CC CC CC 57 56 8B 74 24 10 8B 4C 24 14 8B 7C 24 0C 8B C1 8B D1 03 C6 3B FE 76 08 3B F8 0F 82 68 03 00 00 0F BA 25 FC 31 4C 00 01 73 07 F3 A4 E9 17 03 00 00 81 F9 80 00 00 00 0F 82 CE 01 00 00 8B C7 33 C6 A9 0F 00 00 00 75 0E 0F BA 25 24 E3 4B 00 01 0F 82 DA 04 00 00 0F BA 25 FC 31 4C 00 }
        $s1 = "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO" 
        $s2 = "3!3%3)3-3135393=3A3E3I3M3Q3U3Y3]3a3e3i3m3q3u3y3"
        $s3 = "WaitForThreadpoolTimerCallbacks"
        $s4 = "0!0&0,04090?0G0L0R0Z0_0e0m0r0x0"
        $s5 = "Wow64DisableWow64FsRedirection"
        $s6 = "________________________________" 
        $s7 = "JanFebMarAprMayJunJulAugSepOctNovDec" 
        $s8 = "InitializeSecurityDescriptor"
        $s9 = "InitializeCriticalSectionEx" 
        $s10 = "InitiateSystemShutdownExW" 
    condition:
        pe.is_pe and
        pe.entry_point == 0x271CD and
        $EP at (pe.entry_point) and
        uint32(0x138) == 0x00027DCD and//Optional Header's EP 
        uint32(0x140) == 0x0008F000 and//Optional Header's Base of Data
        pe.timestamp == 0x576812D4 and
        pe.data_directories[1].virtual_address == 0xBA44C and pe.data_directories[1].size == 0x17C and
        pe.data_directories[2].virtual_address == 0xC7000 and pe.data_directories[2].size >= 0x37A000 and pe.data_directories[2].size <= 0x37AFFF and 
        pe.data_directories[5].virtual_address == 0x442000 and pe.data_directories[5].size == 0x711C and
        pe.data_directories[6].virtual_address == 0x92BC0 and pe.data_directories[6].size == 0x1C and
        pe.imports("OLEAUT32.dll") and
        pe.imports("COMDLG32.dll", "GetOpenFileNameW") and
        math.entropy(0, filesize) >= 7.78 and math.entropy(0, filesize) <= 7.88 and
        filesize >= 4300 * 1024 and filesize <= 4400 * 1024 and
        9 of ($s*)
}
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
rule Virus_Rat_v8_0_Beta
{
    meta:
        description = "Detects Virus_Rat_v8_0_Beta malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 50 B8 42 00 00 00 00 00 00 00 00 00 24 B8 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
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
        pe.entry_point == 0x29A42 and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002B842 and//Optional Header's EP 
        uint32(0xB0) == 0x0002C000 and//Optional Header's Base of Data
        pe.timestamp == 0x51543BA3 and
        pe.data_directories[1].virtual_address == 0x2B7F4 and pe.data_directories[1].size == 0x4C and
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
rule Buschtrommel_1_0_TNG
{
    meta:
        description = "Detects Buschtrommel_1_0_TNG malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 C4 F4 B8 E0 A0 45 00 E8 5C C0 FA FF A1 20 C8 45 00 8B 00 E8 64 47 FE FF 8B 0D E0 C8 45 00 A1 20 C8 45 00 8B 00 8B 15 A0 38 45 00 E8 64 47 FE FF A1 20 C8 45 00 8B 00 E8 D8 47 FE FF E8 EB 95 FA FF 8D 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 00 3C 7A 3E }
        $s1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
        $s2 = "\\Hardware\\Description\\System\\CentralProcessor\\0"
        $s3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s4 = ">$>,>0>4>8><>@>D>H>L>P>T>X>\\>`>d>h>l>p>t>x>|>"
        $s5 = "6165696=6A6E6I6M6Q6U6Y6]6a6e6i6m6q6u6"
        $s6 = "+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|" 
        $s7 = ";$;(;0;4;<;@;H;L;T;X;`;d;l;p;x;|;" 
        $s8 = "EInvalidGraphicOperation"
        $s9 = "CreateToolhelp32Snapshot" 
        $s10 = "9,1NEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEONEON" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x59660 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0005A260 and//Optional Header's EP 
        uint32(0x130) == 0x0005B000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x5E000 and pe.data_directories[1].size == 0x2344 and
        pe.data_directories[2].virtual_address == 0x69000 and pe.data_directories[2].size == 0x5E00 and
        pe.data_directories[5].virtual_address == 0x63000 and pe.data_directories[5].size == 0x5E44 and
        pe.data_directories[9].virtual_address == 0x62000 and pe.data_directories[9].size == 0x18 and
        pe.imports("netapi32.dll") and
        pe.imports("winmm.dll", "sndPlaySoundA") and
        math.entropy(0, filesize) >= 6.51 and math.entropy(0, filesize) <= 6.61 and
        filesize >= 417 * 1024 and filesize <= 427 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x69600 and
        8 of ($s*)
}
rule Buschtrommel_1_21
{
    meta:
        description = "Detects Buschtrommel_1_21 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "28-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 40 46 00 8D BE 00 D0 F9 FF C7 87 D0 44 08 00 A0 F6 58 BA 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 }
        $Overlay = { 00 32 AD AC AF 30 39 3E 30 34 43 42 48 51 65 70 }
        $s1 = "fah348hfajk823rhaksjhfdo8zfhkasfh83fhskjdo2e9jdailwdjowifjowifuwoihoidjafoijfoiwfjoiefjaoisfjeoijfoeifjesoifjeaf"
        $s2 = "09>04CBHQepp}dzgtux573>201;)(+"
        $s3 = "eofk3po03jrpoefjp30j3efofe"
        $s4 = "SOFTWARE\\Borland\\Delph"
        $s5 = "pxDDDDDDDDDDDDDDpx"
        $s6 = "ORT_(^.SCJ_LINESL" 
        $s7 = "RasEnumEntriesA" 
        $s8 = "/f$$336699.bat:"
        $s9 = "3EThreadArray" 
        $s10 = "rasapi32.dll" nocase
    condition:
        pe.is_pe and
        pe.entry_point == 0x37FB0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0009BBB0 and//Optional Header's EP 
        uint32(0x130) == 0x0009C000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x9CA3C and pe.data_directories[1].size == 0x280 and
        pe.data_directories[2].virtual_address == 0x9C000 and pe.data_directories[2].size == 0xA3C and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[9].virtual_address == 0x9BD20 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("winmm.dll", "sndPlaySoundA") and
        math.entropy(0, filesize) >= 7.80 and math.entropy(0, filesize) <= 7.94 and
        filesize >= 220 * 1024 and filesize <= 260 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x39000 and
        8 of ($s*)
}
rule Wormins_RAT_0_8
{
    meta:
        description = "Detects Wormins_RAT_0_8 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator"
        $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $s3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
        $s4 = "updaterstartuputility.Formulario.resources"
        $s5 = ").NETFramework,Version=v4.0,Profile=Client"
        $s6 = "updaterstartuputility.Resources.resources" 
        $s7 = "Microsoft.VisualBasic.ApplicationServices" 
        $s8 = "DataGridViewColumnHeadersHeightSizeMode"
        $s9 = "Microsoft.VisualBasic.CompilerServices" 
        $s10 = "$32504e9e-c949-4c5f-8108-e84d800222a1"
    condition:
        pe.is_pe and
        pe.entry_point == 0x33A1E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0003561E and//Optional Header's EP 
        uint32(0xB0) == 0x00036000 and//Optional Header's Base of Data
        pe.timestamp == 0x554FD664 and
        pe.data_directories[1].virtual_address == 0x355C8 and pe.data_directories[1].size == 0x53 and
        pe.data_directories[2].virtual_address == 0x38000 and pe.data_directories[2].size == 0x1198 and
        pe.data_directories[5].virtual_address == 0x3A000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x36000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 7.0 and math.entropy(0, filesize) <= 7.2 and
        filesize >= 207 * 1024 and filesize <= 217 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x35200 and
        8 of ($s*)
}
rule VanToM_RAT_1_0
{
    meta:
        description = "Detects VanToM_RAT_1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 1C 49 43 00 00 00 00 00 00 00 00 00 F0 48 03 00 00 00 00 00 00 00 00 00 38 4D C1 51 00 00 00 00 02 00 00 00 82 00 00 00 40 49 03 00 40 2B 03 00 52 53 44 53 06 ED BD 14 8B 58 7D 43 A3 59 F5 97 71 14 B6 35 01 00 00 00 43 3A 5C 55 73 65 72 73 5C 56 61 6E 54 6F 4D 5C 44 6F 77 6E 6C 6F 61 64 73 5C 43 6F 6D 70 72 65 73 73 65 64 5C 4D }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s2 = "$D8D715A3-6E5E-11D0-B3F0-00AA003761C5"
        $s3 = "$C6E13380-30AC-11d0-A18C-00A0C9118956"
        $s4 = "$C6E13340-30AC-11d0-A18C-00A0C9118956"
        $s5 = "$B196B28B-BAB4-101A-B69C-00AA00341D07"
        $s6 = "$a2104830-7c70-11cf-8bce-00aa00a3f1a6" 
        $s7 = "$9e5530c5-7034-48b4-bb46-0b8a6efc8e36" 
        $s8 = "$93E5A4E0-2D50-11d2-ABFA-00A0C9C6E38D"
        $s9 = "$670d1d20-a068-11d0-b3f0-00aa003761c5" 
        $s10 = "$56a868b3-0ad4-11ce-b03a-0020af0ba770"
    condition:
        pe.is_pe and
        pe.entry_point == 0x32B0E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0003490E and//Optional Header's EP 
        uint32(0xB0) == 0x00036000 and//Optional Header's Base of Data
        pe.timestamp == 0x51C14D38 and
        pe.data_directories[1].virtual_address == 0x348C0 and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x36000 and pe.data_directories[2].size == 0x1F8EA and
        pe.data_directories[5].virtual_address == 0x56000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x34924 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.88 and math.entropy(0, filesize) <= 5.98 and
        filesize >= 325 * 1024 and filesize <= 335 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x52800 and
        8 of ($s*)
}
rule VanToM_RAT_1_3
{
    meta:
        description = "Detects VanToM_RAT_1_3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 58 F0 42 00 00 00 00 00 00 00 00 00 2C F0 02 00 00 00 00 00 00 00 00 00 D3 28 A2 52 00 00 00 00 02 00 00 00 44 00 00 00 7C F0 02 00 7C D2 02 00 52 53 44 53 63 3A 68 0A 5B 90 8D 48 90 D1 96 0A 88 36 A9 28 01 00 00 00 43 3A 5C 55 73 65 72 73 5C 56 61 6E 54 6F 4D 5C 44 65 73 6B 74 6F 70 5C 56 61 6E 54 6F 4D 20 52 41 54 5C 53 74 75 }
        $Overlay = { 61 62 63 63 62 61 }
        $s1 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s2 = "$D8D715A3-6E5E-11D0-B3F0-00AA003761C5"
        $s3 = "$C6E13380-30AC-11d0-A18C-00A0C9118956"
        $s4 = "$C6E13340-30AC-11d0-A18C-00A0C9118956"
        $s5 = "$B196B28B-BAB4-101A-B69C-00AA00341D07"
        $s6 = "$a2104830-7c70-11cf-8bce-00aa00a3f1a6" 
        $s7 = "$9e5530c5-7034-48b4-bb46-0b8a6efc8e36" 
        $s8 = "$93E5A4E0-2D50-11d2-ABFA-00A0C9C6E38D"
        $s9 = "$670d1d20-a068-11d0-b3f0-00aa003761c5" 
        $s10 = "$56a868b3-0ad4-11ce-b03a-0020af0ba770"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2D24A and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002F04A and//Optional Header's EP 
        uint32(0xB0) == 0x00030000 and//Optional Header's Base of Data
        pe.timestamp == 0x52A228D3 and
        pe.data_directories[1].virtual_address == 0x2EFFC and pe.data_directories[1].size == 0x4C and
        pe.data_directories[2].virtual_address == 0x30000 and pe.data_directories[2].size == 0x3251 and
        pe.data_directories[5].virtual_address == 0x34000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x2F060 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.8 and math.entropy(0, filesize) <= 5.9 and
        filesize >= 189 * 1024 and filesize <= 199 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x30A00 and
        8 of ($s*)
}
rule VanToM_RAT_1_4
{
    meta:
        description = "Detects VanToM_RAT_1_4 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        
        $s1 = "$e46a9787-2b71-444d-a4b5-1fab7b708d6a"
        $s2 = "$D8D715A3-6E5E-11D0-B3F0-00AA003761C5"
        $s3 = "$C6E13380-30AC-11d0-A18C-00A0C9118956"
        $s4 = "$C6E13340-30AC-11d0-A18C-00A0C9118956"
        $s5 = "$B196B28B-BAB4-101A-B69C-00AA00341D07"
        $s6 = "$a2104830-7c70-11cf-8bce-00aa00a3f1a6" 
        $s7 = "$9e5530c5-7034-48b4-bb46-0b8a6efc8e36" 
        $s8 = "$93E5A4E0-2D50-11d2-ABFA-00A0C9C6E38D"
        $s9 = "$670d1d20-a068-11d0-b3f0-00aa003761c5" 
        $s10 = "$56a868b3-0ad4-11ce-b03a-0020af0ba770"
    condition:
        pe.is_pe and
        pe.entry_point >= 0x2A700 and pe.entry_point <= 0x2A7FF and
        $EP at (pe.entry_point) and
        uint32(0xA8) >= 0x0002C500 and uint32(0xA8) <= 0x0002C5FF and//Optional Header's EP 
        uint32(0xB0) == 0x00000000 and//Optional Header's Base of Data
        // no specific date//
        pe.data_directories[1].virtual_address >= 0x2C000 and pe.data_directories[1].virtual_address <= 0x2CFFF and 
        pe.data_directories[1].size >= 0x40 and pe.data_directories[1].size <= 0x60 and
        pe.data_directories[2].virtual_address == 0x2E000 and pe.data_directories[2].size >= 0x3200 and pe.data_directories[2].size <= 0x3300 and
        pe.data_directories[5].virtual_address == 0x32000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.7 and math.entropy(0, filesize) <= 5.9 and
        filesize >= 178 * 1024 and filesize <= 188 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}
rule Alusinus_RAT_v0_1
{
    meta:
        description = "Detects Alusinus_RAT_v0_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 70 41 00 8D BE 00 A0 FE FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 4F E6 01 00 57 83 C3 04 53 68 BA 92 00 00 56 83 C3 04 53 50 C7 03 03 00 00 00 90 90 90 90 90 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 78 B8 01 00 00 00 0F B6 }
        
        $s1 = "InternetGetConnectedState"
        $s2 = "xuFuncionesEncriptacion"
        $s3 = "uDatosOrdenador"
        $s4 = "VirtualProtect"
        $s5 = "GetProcAddress"
        $s6 = "VirtualAlloc" 
        $s7 = "oleaut32.dll" nocase 
        $s8 = "LoadLibraryA"
        $s9 = "KERNEL32.DLL" nocase  
        $s10 = "VirtualFree"
    condition:
        pe.is_pe and
        pe.entry_point == 0x96C0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000202C0 and//Optional Header's EP 
        uint32(0x130) == 0x00021000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x22350 and pe.data_directories[1].size == 0x1C0 and
        pe.data_directories[2].virtual_address == 0x21000 and pe.data_directories[2].size == 0x1350 and
        pe.data_directories[5].virtual_address == 0x22510 and pe.data_directories[5].size == 0x10 and
        pe.data_directories[9].virtual_address == 0x20EA8 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 7.59 and math.entropy(0, filesize) <= 7.69 and
        filesize >= 41 * 1024 and filesize <= 51 * 1024 and
        pe.overlay.offset == 0xBA00 and
        8 of ($s*)
}
rule Alusinus_RAT_v0_3
{
    meta:
        description = "Detects Alusinus_RAT_v0_3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 F0 45 00 8D BE 00 20 FA FF C7 87 C0 20 07 00 98 82 C2 B6 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 A7 C4 08 00 57 83 C3 04 53 68 48 F1 02 00 56 83 C3 04 53 50 C7 03 03 00 00 00 90 90 90 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 78 B8 01 00 00 00 0F B6 4A 02 89 C3 D3 E3 89 D9 }
        
        $s1 = "InternetGetConnectedState"
        $s2 = "xuFuncionesEncriptacion"
        $s3 = "uDatosOrdenador"
        $s4 = "VirtualProtect"
        $s5 = "GetProcAddress"
        $s6 = "VirtualAlloc" 
        $s7 = "oleaut32.dll" nocase 
        $s8 = "LoadLibraryA"
        $s9 = "KERNEL32.DLL" nocase  
        $s10 = "VirtualFree"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2F550 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0008E150 and//Optional Header's EP 
        uint32(0x130) == 0x0008F000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x943D8 and pe.data_directories[1].size == 0x33C and
        pe.data_directories[2].virtual_address == 0x8F000 and pe.data_directories[2].size == 0x53D8 and
        pe.data_directories[5].virtual_address == 0x94714 and pe.data_directories[5].size == 0x10 and
        pe.data_directories[9].virtual_address == 0x8ED40 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 7.78 and math.entropy(0, filesize) <= 7.88 and
        filesize >= 209 * 1024 and filesize <= 219 * 1024 and
        pe.overlay.offset == 0x35A00 and
        8 of ($s*)
}
rule Alusinus_RAT_v0_6
{
    meta:
        description = "Detects Alusinus_RAT_v0_6 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 30 46 00 8D BE 00 E0 F9 FF C7 87 C0 60 07 00 D4 13 52 FA 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 4B 17 09 00 57 83 C3 04 53 68 EF 00 03 00 56 83 C3 04 53 50 C7 03 03 00 00 00 90 90 90 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 }
        
        $s1 = "InternetGetConnectedState"
        $s2 = "xuFuncionesEncriptacion"
        $s3 = "uDatosOrdenador"
        $s4 = "VirtualProtect"
        $s5 = "GetProcAddress"
        $s6 = "VirtualAlloc" 
        $s7 = "oleaut32.dll" nocase 
        $s8 = "LoadLibraryA"
        $s9 = "KERNEL32.DLL" nocase  
        $s10 = "VirtualFree"
    condition:
        pe.is_pe and
        pe.entry_point == 0x30500 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x00093100 and//Optional Header's EP 
        uint32(0x130) == 0x00094000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x99408 and pe.data_directories[1].size == 0x380 and
        pe.data_directories[2].virtual_address == 0x94000 and pe.data_directories[2].size == 0x5408 and
        pe.data_directories[5].virtual_address == 0x99788 and pe.data_directories[5].size == 0x10 and
        pe.data_directories[9].virtual_address == 0x93CF0 and pe.data_directories[9].size == 0x18 and
        pe.imports("wsock32.dll") and
        pe.imports("wininet.dll", "InternetGetConnectedState") and
        math.entropy(0, filesize) >= 7.79 and math.entropy(0, filesize) <= 7.89 and
        filesize >= 213 * 1024 and filesize <= 223 * 1024 and
        pe.overlay.offset == 0x36A00 and
        8 of ($s*)
}
rule Alusinus_RAT_v0_9
{
    meta:
        description = "Detects Alusinus_RAT_v0_9 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 60 BE 00 60 46 00 8D BE 00 B0 F9 FF 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 28 8B 1E 83 EE FC 11 DB 72 1F 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 EB 52 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 46 }
        
        $s1 = "|rrrrxtplrrrrhd`\\rrrrXTPL99"
        $s2 = "SOFTWARE\\Borland\\Delphi\\RT"
        $s3 = "NtUnmapViewOfSection"
        $s4 = "GetLongPathNameAbq"
        $s5 = "ZwUnmapViewOfS"
        $s6 = "VirtualProtect" 
        $s7 = "advapi32.dll" nocase 
        $s8 = "GetProcAddress"
        $s9 = "KERNEL32.DLL" nocase  
        $s10 = "RegCloseKey"
    condition:
        pe.is_pe and
        pe.entry_point == 0x47960 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000AD560 and//Optional Header's EP 
        uint32(0x130) == 0x000AE000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0xAE314 and pe.data_directories[1].size == 0x1C0 and
        pe.data_directories[2].virtual_address == 0xAE000 and pe.data_directories[2].size == 0x314 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[9].virtual_address == 0xAD708 and pe.data_directories[9].size == 0x18 and
        pe.imports("oleaut32.dll") and
        pe.imports("ntdll.dll", "NtUnmapViewOfSection") and
        math.entropy(0, filesize) >= 7.88 and math.entropy(0, filesize) <= 7.98 and
        filesize >= 283 * 1024 and filesize <= 293 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}
rule Bandook_v1_0
{
    meta:
        description = "Detects Bandook_v1_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "29-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 87 25 EC 46 40 00 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3A AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 24 AC D1 E8 74 2D 13 C9 EB 18 91 48 C1 E0 08 AC FF 53 04 3B 43 F8 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 9F 5E AD 97 }
        $s5 = "FSG!"
        $s1 = "GetProcAddress"
        $s2 = "s$iHM"
        $s3 = "cons1|"
        $s4 = "KERNEL32.dll" nocase
        $s6 = "LoadLibraryA"
    condition:
        pe.is_pe and
        pe.entry_point == 0x154 and
        $EP at (pe.entry_point) and
        uint32(0x34) == 0x00000154 and//Optional Header's EP 
        uint32(0x3C) == 0x0000000C and//Optional Header's Base of Data
        pe.timestamp == 0x21475346 and
        pe.data_directories[1].virtual_address == 0x46A8 and pe.data_directories[1].size == 0x84 and
        pe.data_directories[2].virtual_address == 0x0 and pe.data_directories[2].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[9].virtual_address == 0x0 and pe.data_directories[9].size == 0x0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        math.entropy(0, filesize) >= 7.0 and math.entropy(0, filesize) <= 7.1 and
        filesize >= 0 * 1024 and filesize <= 10 * 1024 and
        pe.overlay.size == 0 and
        5 of ($s*)
}
rule Bandook_v1_1
{
    meta:
        description = "Detects Bandook_v1_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "30-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 87 25 80 7C 14 13 61 94 55 A4 B6 80 FF 13 73 F9 }
        $s5 = "FSG!"
        $s1 = "GetProcAddress"
        $s2 = "ns1|"
        $s3 = "]`myco"
        $s4 = "KERNEL32.dll" nocase
        $s6 = "LoadLibraryA"
    condition:
        pe.is_pe and
        pe.entry_point == 0x154 and
        $EP at (pe.entry_point) and
        uint32(0x34) == 0x00000154 and//Optional Header's EP 
        uint32(0x3C) == 0x0000000C and//Optional Header's Base of Data
        pe.timestamp == 0x21475346 and
        pe.data_directories[1].virtual_address >= 0x7C00 and pe.data_directories[1].virtual_address <= 0x7CFF and pe.data_directories[1].size == 0x84 and
        pe.data_directories[2].virtual_address == 0x0 and pe.data_directories[2].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[9].virtual_address == 0x0 and pe.data_directories[9].size == 0x0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        math.entropy(0, filesize) >= 7.39 and math.entropy(0, filesize) <= 7.49 and
        filesize >= 0 * 1024 and filesize <= 10 * 1024 and
        pe.overlay.size == 0 and
        4 of ($s*)
}
rule Bandook_v1_2
{
    meta:
        description = "Detects Bandook_v1_2 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "30-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 87 25 ?? 72 14 13 61 94 55 A4 B6 80 FF 13 73 F9 }
        $s5 = "FSG!"
        $s1 = "GetProcAddress"
        $s2 = "i$_HU"
        $s3 = "mycon"
        $s4 = "KERNEL32.dll" nocase
        $s6 = "LoadLibraryA"
    condition:
        pe.is_pe and
        pe.entry_point == 0x154 and
        $EP at (pe.entry_point) and
        uint32(0x34) == 0x00000154 and//Optional Header's EP 
        uint32(0x3C) == 0x0000000C and//Optional Header's Base of Data
        pe.timestamp == 0x21475346 and
        pe.data_directories[1].virtual_address >= 0x7200 and pe.data_directories[1].virtual_address <= 0x72FF and pe.data_directories[1].size == 0x84 and
        pe.data_directories[2].virtual_address == 0x0 and pe.data_directories[2].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[9].virtual_address == 0x0 and pe.data_directories[9].size == 0x0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        math.entropy(0, filesize) >= 7.58 and math.entropy(0, filesize) <= 7.68 and
        filesize >= 0 * 1024 and filesize <= 10 * 1024 and
        pe.overlay.size == 0 and
        5 of ($s*)
}
rule Arcom_V1_3
{
    meta:
        description = "Detects Arcom_V1_3 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "30-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 05 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 2C 87 45 00 E8 1C D0 FA FF 33 C0 55 68 C7 99 45 00 64 FF 30 64 89 20 33 D2 55 68 7C 99 45 00 64 FF 32 64 89 22 E8 E7 EE FF FF 33 C9 B2 01 A1 24 A1 44 00 E8 59 38 FF FF E8 50 69 FB FF B8 30 75 00 00 E8 DE 78 FB FF B2 01 A1 F4 09 41 00 E8 1A 75 FB FF 8B D8 33 D2 8B C3 E8 7B 75 FB }
        $Overlay = { F0 03 00 00 00 02 02 00 30 82 03 DE 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 03 CF 30 82 03 CB 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 68 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 5A 30 }
        $s5 = "Jh739ehSDjei393jHfjhejh3u3jfnBFHJHJEFHJuu33iufnj3ujfnfjdcndhjwu3iu3juuU3u3u3udbdhj3ehjdhhfhesh34ufbfsdjsjdadadu3uadjeu3ufhfh"
        $s1 = "GetThemeDocumentationProperty"
        $s2 = "DwmExtendFrameIntoClientArea"
        $s3 = "TAdvancedMenuDrawItemEvent"
        $s4 = "KERNEL32.dll" nocase
        $s6 = "IsThemeBackgroundPartiallyTransparent"
        $s7 = "$TMultiReadExclusiveWriteSynchronizer"
        $s8 = "iMi23CITZ31BLk6M1Qw8BbYQhAHr6YqK"
        $s9 = "comctl32.dll" nocase
        $s10 = "clGradientInactiveCaption"
    condition:
        pe.is_pe and
        pe.entry_point == 0x585B0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000597B0 and//Optional Header's EP 
        uint32(0x130) == 0x0005A000 and//Optional Header's Base of Data
        pe.timestamp == 0x4F737F83 and
        pe.data_directories[1].virtual_address == 0x62000 and pe.data_directories[1].size == 0x25DC and
        pe.data_directories[2].virtual_address == 0x6D000 and pe.data_directories[2].size == 0xA3C00 and
        pe.data_directories[4].virtual_address == 0x107A00 and pe.data_directories[4].size == 0x3F0 and
        pe.data_directories[5].virtual_address == 0x67000 and pe.data_directories[5].size == 0x5CE4 and
        pe.data_directories[9].virtual_address == 0x66000 and pe.data_directories[9].size == 0x18 and
        pe.imports("kernel32.dll") and
        pe.imports("shell32.dll", "SHGetSpecialFolderLocation") and
        math.entropy(0, filesize) >= 7.4 and math.entropy(0, filesize) <= 7.5 and
        filesize >= 1050 * 1024 and filesize <= 1060 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x107A00 and
        8 of ($s*)
}
rule Arcom_V1_5
{
    meta:
        description = "Detects Arcom_V1_5 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "30-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 05 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 DC 86 45 00 E8 1C D0 FA FF 33 C0 55 68 C7 99 45 00 64 FF 30 64 89 20 33 D2 55 68 7C 99 45 00 64 FF 32 64 89 22 E8 97 EE FF FF 33 C9 B2 01 A1 D4 A0 44 00 E8 09 38 FF FF E8 8C 68 FB FF B8 30 75 00 00 E8 D2 78 FB FF B2 01 A1 30 09 41 00 E8 56 74 FB FF 8B D8 33 D2 8B C3 E8 B7 74 FB }
        $Overlay = { 58 04 00 00 00 02 02 00 30 82 04 4A 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 04 3B 30 82 04 37 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 }
        $s5 = "ki9393jujdjdjdjDHjjhdjhfj8883hDjhjdHuhfuUUueeuu3u3u3u3dfHFHHFUueuu3ufhFHHFFHHF483838fhfjFHJjfhjFHu3883dfhJFhe8u3jehdude84ufhFu"
        $s1 = "IsThemeBackgroundPartiallyTransparent"
        $s2 = "DwmExtendFrameIntoClientArea"
        $s3 = "TAdvancedMenuDrawItemEvent"
        $s4 = "KERNEL32.dll" nocase
        $s6 = "IsThemeBackgroundPartiallyTransparent"
        $s7 = "$TMultiReadExclusiveWriteSynchronizer"
        $s8 = "GetThemeBackgroundContentRect"
        $s9 = "shell32.dll" nocase
        $s10 = "clGradientInactiveCaption"
    condition:
        pe.is_pe and
        pe.entry_point == 0x585B0 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x000597B0 and//Optional Header's EP 
        uint32(0x130) == 0x0005A000 and//Optional Header's Base of Data
        pe.timestamp == 0x4FDA2EC1 and
        pe.data_directories[1].virtual_address == 0x62000 and pe.data_directories[1].size == 0x25DC and
        pe.data_directories[2].virtual_address == 0x6D000 and pe.data_directories[2].size == 0x96000 and
        pe.data_directories[4].virtual_address == 0xF9E00 and pe.data_directories[4].size == 0x458 and
        pe.data_directories[5].virtual_address == 0x67000 and pe.data_directories[5].size == 0x5CF4 and
        pe.data_directories[9].virtual_address == 0x66000 and pe.data_directories[9].size == 0x18 and
        pe.imports("kernel32.dll") and
        pe.imports("shell32.dll", "SHGetPathFromIDListA") and
        math.entropy(0, filesize) >= 7.41 and math.entropy(0, filesize) <= 7.51 and
        filesize >= 990 * 1024 and filesize <= 1010 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0xF9E00 and
        8 of ($s*)
}
rule SharpEye_Rat_1_0_Beta_1
{
    meta:
        description = "Detects SharpEye_Rat_1_0_Beta_1 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "30-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC B9 0B 00 00 00 6A 00 6A 00 49 75 F9 53 B8 A4 EF 45 00 E8 8E 77 FA FF BB E4 84 46 00 33 C0 55 68 3B F5 45 00 64 FF 30 64 89 20 A1 B0 44 46 00 BA 50 F5 45 00 E8 88 56 FA FF A1 B0 44 46 00 BA 64 F5 45 00 E8 79 56 FA FF A1 94 43 46 00 BA 88 F5 45 00 E8 6A 56 FA FF A1 BC 43 46 00 BA A0 F5 45 00 E8 5B 56 FA FF A1 BC 43 46 00 BA C8 }
        $s1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" nocase 
        $s2 = "SAKA-TAMAM|KLAVYE_ISIKLARI_AC_KAPA_4EVER|DEACTIVE" nocase 
        $s3 = "SAKA-TAMAM|KLAVYE_ISIKLARI_AC_KAPA_4EVER|ACTIVE" nocase
        $s4 = "DY-YUKLU_PROGRAMLAR_or_DOSYA_ARAMA_or_NEYSE" nocase
        $s5 = "$TMultiReadExclusiveWriteSynchronizer"
        $s6 = "VERILER_SADECE_MEMDE_TUTULCAK" nocase  
        $s7 = "ARAMA_KALINTILARINI_YOK_ET" nocase 
        $s8 = "clGradientInactiveCaption"
        $s9 = "KERNEL32.DLL" nocase  
        $s10 = ">:ISLEM:>KUCULT<?ISLEM?<"
    condition:
        pe.is_pe and
        pe.entry_point == 0x5E5B4 and
        $EP at (pe.entry_point) and
        uint32(0x128) == 0x0005F1B4 and//Optional Header's EP 
        uint32(0x130) == 0x00060000 and//Optional Header's Base of Data
        pe.timestamp == 0x2A425E19 and
        pe.data_directories[1].virtual_address == 0x69000 and pe.data_directories[1].size == 0x220C and
        pe.data_directories[2].virtual_address == 0x73000 and pe.data_directories[2].size == 0x2BA8 and
        pe.data_directories[5].virtual_address == 0x6E000 and pe.data_directories[5].size == 0x4EA8 and
        pe.data_directories[9].virtual_address == 0x6D000 and pe.data_directories[9].size == 0x18 and
        pe.imports("winmm.dll") and
        pe.imports("kernel32.dll", "IsDebuggerPresent") and
        math.entropy(0, filesize) >= 6.46 and math.entropy(0, filesize) <= 6.56 and
        filesize >= 432 * 1024 and filesize <= 442 * 1024 and
        pe.overlay.size == 0 and
        8 of ($s*)
}
rule SpyGate_RAT_v_0_2_6
{
    meta:
        description = "Detects SpyGate_RAT_v_0_2_6 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "30-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $Overlay = { 61 62 63 63 62 61 }
        $s5 = "C:\\Users\\Umbrella\\Desktop\\StubX\\StubX\\obj\\Debug\\StubX.pdb"
        $s1 = "$29c41831-494d-4bcf-93ea-14ce03a5553c"
        $s2 = "m_MyWebServicesObjectProvider"
        $s3 = "DebuggerNonUserCodeAttribute"
        $s4 = "CRYPTPROTECT_PROMPT_ON_PROTECT" nocase
        $s6 = "StubX.Resources.resources"
        $s7 = "set_SaveMySettingsOnExit"
        $s8 = "PK11_GetInternalKeySlot"
        $s9 = "NSSBase64_DecodeBuffer"
        $s10 = "StubX.Form1.resources"
    condition:
        pe.is_pe and
        pe.entry_point == 0x2088E and
        $EP at (pe.entry_point) and
        uint32(0xA8) == 0x0002248E and//Optional Header's EP 
        uint32(0xB0) == 0x00024000 and//Optional Header's Base of Data
        pe.timestamp == 0x51C656FA and
        pe.data_directories[1].virtual_address == 0x22434 and pe.data_directories[1].size == 0x57 and
        pe.data_directories[2].virtual_address == 0x26000 and pe.data_directories[2].size == 0x562 and
        pe.data_directories[4].virtual_address == 0x0 and pe.data_directories[4].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x28000 and pe.data_directories[5].size == 0xC and
        pe.data_directories[6].virtual_address == 0x24000 and pe.data_directories[6].size == 0x1C and
        pe.imports("mscoree.dll") and
        pe.imports("mscoree.dll", "_CorExeMain") and
        math.entropy(0, filesize) >= 5.67 and math.entropy(0, filesize) <= 5.77 and
        filesize >= 128 * 1024 and filesize <= 138 * 1024 and
        $Overlay in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size) and 
        pe.overlay.offset == 0x21400 and
        8 of ($s*)
}
rule C_One_v1_0_0
{
    meta:
        description = "Detects C_One_v1_0_0 malware builder's malware, special for that variant of builder"
        author = "GokbakarE"
        date = "25-06-2025"
        license = "GNU AGPLv3"
    strings:
        $EP = { 55 8B EC 83 EC 44 56 FF 15 8C 10 40 00 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D 46 EB 0A 3C 20 7E 06 46 80 3E 20 7F FA 8A 06 84 C0 74 04 3C 20 7E E9 83 65 E8 00 8D 45 BC 50 FF 15 90 10 40 00 E8 5D 00 00 00 68 AC 10 40 00 68 A8 10 40 00 E8 34 00 00 00 F6 45 E8 01 59 59 74 06 0F B7 45 EC EB 03 6A 0A 58 }
        $EP2 = { 87 25 08 62 40 00 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3A AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 24 AC D1 E8 74 2D 13 C9 EB 18 91 48 C1 E0 08 AC FF 53 04 3B 43 F8 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 9F 5E AD 97 }

        $s1 = "GetProcAddress" 
        $s2 = "LoadLibraryA" 
        $s3 = "KERNEL32.dll" nocase
        $s4 = "_^[Y" 
    condition:
        pe.is_pe and
        (pe.entry_point == 0x154 or pe.entry_point == 0x1E78) and
        ($EP at (pe.entry_point) or $EP2 at (pe.entry_point)) and
        (uint32(0x34) == 0x00000154 or uint32(0xE8) == 0x00002C78) and//Optional Header's EP 
        (uint32(0x3C) == 0x0000000C or uint32(0xF0) == 0x00001000) and//Optional Header's Base of Data
        (pe.timestamp == 0x21475346 or pe.timestamp == 0x42FA3577) and
        (pe.data_directories[1].virtual_address == 0x2D84 and pe.data_directories[1].size == 0x3C or pe.data_directories[1].virtual_address == 0x61C4 and pe.data_directories[1].size == 0x84) and
        pe.data_directories[2].virtual_address == 0x0 and pe.data_directories[2].size == 0x0 and
        pe.data_directories[5].virtual_address == 0x0 and pe.data_directories[5].size == 0x0 and
        pe.data_directories[6].virtual_address == 0x0 and pe.data_directories[6].size == 0x0 and
        pe.imports("KERNEL32.dll") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        (math.entropy(0, filesize) >= 5.89 and math.entropy(0, filesize) <= 5.99 or math.entropy(0, filesize) >= 7.55 and math.entropy(0, filesize) <= 7.65) and
        filesize >= 1 * 1024 and filesize <= 15 * 1024 and
        4 of ($s*)
}