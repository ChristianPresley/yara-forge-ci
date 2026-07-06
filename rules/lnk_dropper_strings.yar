/*
    Detection idea: "ISO/LNK dropper" tradecraft where a shortcut or container
    quietly spawns a script host that pivots into a hidden PowerShell/mshta stage.
    This rule keys on the command-line artifact commonly embedded in weaponized
    LNK files and container droppers (cmd /c, wscript, mshta + hidden window).

    Performance notes:
    - Focuses on the co-occurrence of a script host and a stealth flag
      (-w hidden, -nop, WindowStyle Hidden), which is the discriminating signal.
    - Avoids matching "cmd" alone; requires the /c or /k execution switch context.
*/

rule LNK_ScriptHost_Dropper
{
    meta:
        author        = "Christian Presley"
        date          = "2026-05-14"
        description   = "Detects LNK/container dropper command lines spawning hidden script hosts"
        reference     = "https://attack.mitre.org/techniques/T1204/002/"
        mitre_attack  = "T1204.002"
        severity      = "high"
        version       = "1.0"

    strings:
        // Script / execution hosts
        $host1 = "mshta.exe" nocase ascii wide
        $host2 = "wscript.exe" nocase ascii wide
        $host3 = "cscript.exe" nocase ascii wide
        $host4 = "rundll32.exe" nocase ascii wide
        $host5 = /cmd(\.exe)?\s+\/[ck]\b/ nocase ascii wide

        // Stealth / execution-policy-defeating flags
        $stealth1 = "-w hidden" nocase ascii wide
        $stealth2 = "-WindowStyle Hidden" nocase ascii wide
        $stealth3 = "-nop" nocase ascii wide
        $stealth4 = "-NoProfile" nocase ascii wide
        $stealth5 = "-ExecutionPolicy Bypass" nocase ascii wide
        $stealth6 = "vbscript:" nocase ascii wide

    condition:
        1 of ($host*) and 1 of ($stealth*)
}
