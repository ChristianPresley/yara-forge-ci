/*
    Detection idea: Classic PHP webshell pattern - dynamic code execution fed by
    an obfuscated (base64 / gzip) payload sourced from request superglobals.
    Covers the eval(base64_decode($_POST[...])) family and its gzinflate variants.

    Performance notes:
    - Anchors on the specific sink+source pairing rather than "eval" alone, which
      alone would be far too noisy in legitimate PHP.
    - Regex uses bounded whitespace classes (\s*) around fixed tokens to stay linear.
*/

rule Webshell_PHP_Eval_Base64
{
    meta:
        author        = "Christian Presley"
        date          = "2026-05-14"
        description   = "Detects PHP webshells combining eval/assert with base64/gzip decode of request input"
        reference     = "https://attack.mitre.org/techniques/T1505/003/"
        mitre_attack  = "T1505.003"
        severity      = "high"
        version       = "1.0"

    strings:
        $php = "<?php" nocase ascii

        // Dynamic execution sinks
        $sink1 = /\beval\s*\(/ nocase ascii
        $sink2 = /\bassert\s*\(/ nocase ascii
        $sink3 = /\bcreate_function\s*\(/ nocase ascii
        $sink4 = /\bpreg_replace\s*\(\s*['"].{0,64}\/e['"]/ nocase ascii   // legacy /e modifier RCE

        // Obfuscation decoders frequently wrapping attacker input
        $dec1 = "base64_decode" nocase ascii
        $dec2 = "gzinflate" nocase ascii
        $dec3 = "str_rot13" nocase ascii
        $dec4 = "gzuncompress" nocase ascii

        // Request-borne input sources
        $src1 = "$_POST" ascii
        $src2 = "$_GET" ascii
        $src3 = "$_REQUEST" ascii
        $src4 = "$_COOKIE" ascii

    condition:
        $php
        and 1 of ($sink*)
        and 1 of ($dec*)
        and 1 of ($src*)
}
