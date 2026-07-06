/*
    Detection idea: In-memory AMSI (Antimalware Scan Interface) tampering. The
    canonical bypass patches amsi.dll!AmsiScanBuffer or nulls the amsiInitFailed
    field via reflection. These specific reflection strings are extremely rare in
    benign code and highly indicative of evasion.

    Performance notes:
    - "AmsiScanBuffer" and "amsiInitFailed" are long, unique atoms.
    - GetProcAddress / GetField are common, so they are only used as corroborating
      conditions, never as sole triggers.
*/

rule PowerShell_AMSI_Bypass
{
    meta:
        author        = "Christian Presley"
        date          = "2026-05-14"
        description   = "Detects reflective AMSI bypass patterns in PowerShell/.NET"
        reference     = "https://attack.mitre.org/techniques/T1562/001/"
        mitre_attack  = "T1562.001"
        severity      = "critical"
        version       = "1.0"

    strings:
        $amsi1 = "AmsiScanBuffer" ascii wide
        $amsi2 = "amsiInitFailed" nocase ascii wide
        $amsi3 = "AmsiUtils" ascii wide
        $amsi4 = "System.Management.Automation.AmsiUtils" ascii wide

        // Reflection primitives used to reach the private field / patch the DLL.
        $refl1 = "GetField" ascii wide
        $refl2 = "SetValue" ascii wide
        $refl3 = "VirtualProtect" nocase ascii wide
        $refl4 = "GetProcAddress" nocase ascii wide
        $refl5 = "NonPublic" ascii wide

    condition:
        // A concrete AMSI reference plus at least one reflection/patch primitive.
        1 of ($amsi*) and 1 of ($refl*)
}
