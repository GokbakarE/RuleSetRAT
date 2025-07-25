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
