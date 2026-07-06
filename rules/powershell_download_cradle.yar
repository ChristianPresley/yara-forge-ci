/*
    Detection idea: PowerShell "download cradle" one-liners that fetch and execute
    remote payloads in memory. These are a staple of fileless intrusions and
    commodity loaders (e.g. IEX (New-Object Net.WebClient).DownloadString(...)).

    Performance notes:
    - Every atom is a long, distinctive method name (DownloadString, DownloadFile,
      Invoke-Expression), all >= 4 bytes and highly selective.
    - The IEX alias is guarded by a word-boundary-ish regex to reduce noise.
*/

rule PowerShell_DownloadCradle
{
    meta:
        author        = "Christian Presley"
        date          = "2026-05-14"
        description   = "Detects in-memory PowerShell download-and-execute cradles"
        reference     = "https://attack.mitre.org/techniques/T1059/001/"
        mitre_attack  = "T1059.001"
        severity      = "high"
        version       = "1.0"

    strings:
        // Fetch primitives
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "DownloadFile" nocase ascii wide
        $dl3 = "DownloadData" nocase ascii wide
        $dl4 = "Net.WebClient" nocase ascii wide
        $dl5 = "Invoke-WebRequest" nocase ascii wide
        $dl6 = "Invoke-RestMethod" nocase ascii wide

        // Execute primitives
        $ex1 = "Invoke-Expression" nocase ascii wide
        $ex2 = /\bIEX\s*[\(\$]/ nocase ascii
        $ex3 = "| iex" nocase ascii wide

    condition:
        // Something that fetches remote content AND something that runs it.
        1 of ($dl*) and 1 of ($ex*)
}
