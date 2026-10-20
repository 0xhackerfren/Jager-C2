rule Jager_Hardcoded_Defaults {
    meta:
        description = "Detects multiple default Jager-C2 strings (not polymorphized)"
        severity = "high"
    strings:
        $pipe = "jager-p2p" ascii wide
        $agent = "Jager/" ascii
        $build_id = "jager-build" ascii
    condition:
        2 of them
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


rule Jager_VEH_Registration {
    meta:
        description = "Direct VEH registration pattern"
        severity = "medium"
    strings:
        $veh = "AddVectoredExceptionHandler"
    condition:
        $veh
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
