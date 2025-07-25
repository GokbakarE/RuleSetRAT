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
