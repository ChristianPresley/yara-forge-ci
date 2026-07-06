/*
    Detection idea: PowerShell launched with an encoded (Base64) command payload.
    Attackers routinely use -EncodedCommand (and its shortenable aliases -enc, -ec)
    to smuggle obfuscated scripts past shell-history and naive logging. Legitimate
    admin scripts almost never need it.

    Performance notes:
    - All string atoms are >= 4 bytes, so YARA can build strong Aho-Corasick atoms.
    - No leading wildcards or unbounded jumps; the base64 blob is matched with a
      bounded regex to avoid catastrophic backtracking on large files.
*/

rule PowerShell_EncodedCommand
{
    meta:
        author        = "Christian Presley"
        date          = "2026-05-14"
        description   = "Detects PowerShell invoked with an encoded (Base64) command payload"
        reference     = "https://attack.mitre.org/techniques/T1059/001/"
        mitre_attack  = "T1059.001"
        severity      = "high"
        version       = "1.0"

    strings:
        // powershell(.exe) invocation - case-insensitive
        $ps1 = "powershell" nocase ascii wide
        $ps2 = "pwsh" nocase ascii wide

        // -EncodedCommand and its common abbreviations. PowerShell accepts any
        // unambiguous prefix, so -enc / -ec are valid and heavily used in the wild.
        $enc1 = "-EncodedCommand" nocase ascii wide
        $enc2 = "-encodedcommand" nocase ascii wide
        $enc3 = /-e(nc|c)(o(m(m(a(n(d)?)?)?)?)?)?\s+[A-Za-z0-9+\/]{40,}={0,2}/ nocase ascii

    condition:
        // A PowerShell host AND either the explicit flag or the encoded-blob shape.
        1 of ($ps*) and 1 of ($enc*)
}
