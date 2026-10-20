import "pe"

rule Jager_AMSI_Patch_Bytes {
    meta:
        description = "Detects AMSI patch byte sequence (PE only)"
        severity = "high"
    strings:
        $amsi_ret = { B8 57 00 07 80 C3 }
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Jager_ETW_Patch_Bytes {
    meta:
        description = "Detects ETW patch byte sequence (PE only)"
        severity = "high"
    strings:
        $etw_xor = { 48 33 C0 C3 }
    condition:
        uint16(0) == 0x5A4D and $etw_xor
}

rule Jager_RWX_Section {
    meta:
        description = "PE has RWX section"
        severity = "critical"
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1):
            (pe.sections[i].characteristics & 0xE0000000 == 0xE0000000)
}

rule Jager_WinHTTP_Import_Combo {
    meta:
        description = "WinHTTP C2 import pattern"
        severity = "medium"
    strings:
        $a = "WinHttpOpen"
        $b = "WinHttpConnect"
        $c = "WinHttpSendRequest"
    condition:
        uint16(0) == 0x5A4D and all of them
}
