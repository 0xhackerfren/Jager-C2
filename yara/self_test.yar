rule Jager_Hardcoded_Defaults {
    meta:
        description = "Detects default Jager-C2 strings that should be randomized"
        severity = "high"
    strings:
        $pipe = "jager-p2p" ascii wide
        $agent = "Jager-C2" ascii
        $api_path1 = "/api/v1/register" ascii
        $api_path2 = "/api/v1/checkin" ascii
        $api_path3 = "/api/v1/result" ascii
        $build_id = "jager-" ascii
    condition:
        any of them
}

rule Jager_Debug_Strings {
    meta:
        description = "Detects debug strings that should be stripped"
        severity = "high"
    strings:
        $debug1 = "beacon registered" ascii
        $debug2 = "task received" ascii
        $debug3 = "sleep_mask" ascii
        $debug4 = "transport_checkin" ascii
    condition:
        any of them
}

rule Jager_AMSI_Patch_Bytes {
    meta:
        description = "Detects AMSI patch byte sequence"
        severity = "high"
    strings:
        $amsi_ret = { B8 57 00 07 80 C3 }
        $amsi_nop = { 48 31 C0 C3 }
    condition:
        any of them
}

rule Jager_ETW_Patch_Bytes {
    meta:
        description = "Detects ETW patch byte sequence"
        severity = "high"
    strings:
        $etw_ret = { C3 }
        $etw_xor = { 48 33 C0 C3 }
    condition:
        all of them
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

rule Jager_VEH_Registration {
    meta:
        description = "Direct VEH registration pattern"
        severity = "medium"
    strings:
        $veh = "AddVectoredExceptionHandler"
    condition:
        $veh
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
        all of them
}

rule Jager_Suspicious_Strings {
    meta:
        description = "Unobfuscated suspicious strings"
        severity = "high"
    strings:
        $s1 = "AmsiScanBuffer" ascii
        $s2 = "EtwEventWrite" ascii
        $s3 = "MiniDumpWriteDump" ascii
        $s4 = "NtProtectVirtualMemory" ascii
    condition:
        2 of them
}
