rule Suspicious_Executable {
    meta:
        description = "Detects Windows PE executables (often hidden in archives)"
        severity = "HIGH"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}

rule Suspicious_Macro_Keywords {
    meta:
        description = "Detects common malicious macro auto-execution triggers"
        severity = "MEDIUM"
    strings:
        $a1 = "AutoOpen" nocase
        $a2 = "Document_Open" nocase
        $a3 = "Workbook_Open" nocase
        $s1 = "Shell" nocase fullword
        $s2 = "WScript.Shell" nocase
        $s3 = "CreateObject" nocase
        $s4 = "powershell" nocase
    condition:
        (1 of ($a*)) and (1 of ($s*))
}

rule Suspicious_PDF_Elements {
    meta:
        description = "Detects PDFs with JavaScript, Launch actions, or EmbeddedFiles"
        severity = "MEDIUM"
    strings:
        $js1 = "/JavaScript"
        $js2 = "/JS"
        $launch = "/Launch"
        $embed = "/EmbeddedFiles"
        $open = "/OpenAction"
    condition:
        any of them
}
