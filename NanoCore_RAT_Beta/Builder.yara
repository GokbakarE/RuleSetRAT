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
