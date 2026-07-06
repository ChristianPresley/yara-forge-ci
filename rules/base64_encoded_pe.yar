/*
    Detection idea: A Windows PE (EXE/DLL) embedded as a Base64 string inside a
    text-based carrier (script, HTML, config, JSON). Loaders frequently ship a
    base64 blob that decodes to an "MZ..." PE header. The Base64 encoding of the
    DOS stub "MZ\x90\x00..." begins with the recognizable prefix "TVqQ" (and the
    generic "MZ" -> "TVo..." family).

    Performance notes:
    - "TVqQAAMAAAAEAAAA" is the base64 of the standard MZ/DOS header + e_lfanew
      layout and is a long, extremely specific atom - near-zero FP.
    - The trailing "This program cannot be run in DOS mode" string, once base64'd,
      starts with "VGhpcyBwcm9ncmFt" which is likewise highly selective.
*/

rule Base64_Encoded_PE_Heuristic
{
    meta:
        author        = "Christian Presley"
        date          = "2026-05-14"
        description   = "Heuristic: Windows PE embedded as a Base64 blob inside a text carrier"
        reference     = "https://attack.mitre.org/techniques/T1027/"
        mitre_attack  = "T1027"
        severity      = "medium"
        version       = "1.0"

    strings:
        // Base64 of a standard MZ DOS header (very common exact prefix).
        $mz_b64_1 = "TVqQAAMAAAAEAAAA" ascii wide
        $mz_b64_2 = "TVpQAAIAAAAEAA8A" ascii wide          // alternate stub layout
        $mz_b64_3 = "TVoAAAAAAAAAAAAA" ascii wide

        // Base64 of "This program cannot be run in DOS mode" (the DOS stub text).
        $dos_b64  = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU" ascii wide

    condition:
        any of them
}
