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