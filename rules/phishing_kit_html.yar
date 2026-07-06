/*
    Detection idea: Credential-harvesting phishing page. Combines a password input
    field, a form that POSTs off-site (or to a PHP collector), and either brand
    impersonation cues or a base64-embedded second stage. Targets the static HTML
    artifact of a phishing kit, which does not require any live infrastructure.

    Performance notes:
    - The base64 blob is length-bounded ({200,}) so it does not scan unbounded.
    - Individual atoms like "type=\"password\"" and "credentials" are selective;
      the multi-condition AND keeps false positives on normal login pages low by
      requiring a collector + an obfuscation/impersonation signal together.
*/

rule Phishing_Kit_CredHarvest_HTML
{
    meta:
        author        = "Christian Presley"
        date          = "2026-05-14"
        description   = "Detects static credential-harvest phishing HTML with off-site POST and second-stage/base64 payload"
        reference     = "https://attack.mitre.org/techniques/T1566/002/"
        mitre_attack  = "T1566.002"
        severity      = "medium"
        version       = "1.0"

    strings:
        // Credential capture form primitives
        $pw    = /type\s*=\s*["']password["']/ nocase ascii
        $form  = /<form[^>]{0,200}method\s*=\s*["']post["']/ nocase ascii

        // Common collector endpoints shipped in kits
        $col1  = "action=\"next.php" nocase ascii
        $col2  = "action=\"login.php" nocase ascii
        $col3  = "action=\"post.php" nocase ascii
        $col4  = "sendmail" nocase ascii
        $col5  = "$message .= \"Email" nocase ascii    // PHP mailer stub inline

        // Second-stage / obfuscation signals
        $b64   = /atob\(\s*["'][A-Za-z0-9+\/]{200,}={0,2}["']/ ascii
        $eval  = "document.write(atob(" nocase ascii

        // Brand impersonation cues (kept as corroboration, never sole trigger)
        $imp1  = "Sign in to your account" nocase ascii
        $imp2  = "Verify your identity" nocase ascii
        $imp3  = "Your session has expired" nocase ascii

    condition:
        $pw and $form
        and (
            1 of ($col*)
            or 1 of ($b64, $eval)
        )
        and (
            1 of ($col*)
            or 1 of ($b64, $eval)
            or 1 of ($imp*)
        )
}
