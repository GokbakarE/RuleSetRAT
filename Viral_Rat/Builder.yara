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
